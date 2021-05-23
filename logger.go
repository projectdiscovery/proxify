package proxify

import (
	"bytes"
	"fmt"
	"github.com/Shopify/sarama"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
)

type OptionsLogger struct {
	Verbose      bool
	OutputFolder string
	OutputKafka  string
}

type OutputData struct {
	userdata UserData
	data     []byte
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan OutputData
}

func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan OutputData, 1000),
	}
	_ = logger.createOutputFolder()
	go logger.AsyncWrite()
	return logger
}

func msg2kafka(content []byte, id string, addr string, topic string) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Return.Successes = true
	config.Producer.Partitioner = sarama.NewRandomPartitioner
	msg := &sarama.ProducerMessage{}
	msg.Topic = topic
	var id_byte []byte = []byte(id + "\r\n")
	join_content := [][]byte{id_byte, content}
	msg.Value = sarama.ByteEncoder(bytes.Join(join_content, []byte{}))
	addrs := strings.Split(addr, ",")
	producer, err := sarama.NewSyncProducer(addrs, config)
	if err != nil {
		log.Print(err)
		return
	}
	defer producer.Close()
	_, _, err = producer.SendMessage(msg)

	if err != nil {
		log.Println(err)
		return
	}

}

func (l *Logger) createOutputFolder() error {
	if l.options.OutputFolder == "" {
		return nil
	}
	return os.MkdirAll(l.options.OutputFolder, 0755)
}

func (l *Logger) AsyncWrite() {
	for outputdata := range l.asyncqueue {
		destFile := path.Join(l.options.OutputFolder, fmt.Sprintf("%s-%s", outputdata.userdata.host, outputdata.userdata.id))
		// if it's a response and file doesn't exist skip
		f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}
		fmt.Fprintf(f, "%s", outputdata.data)
		f.Close()
		if outputdata.userdata.hasResponse {
			outputFileName := destFile + ".txt"
			if outputdata.userdata.match {
				outputFileName = destFile + ".match.txt"
			}
			_ = os.Rename(destFile, outputFileName)
		}
	}
}

func (l *Logger) LogRequest(req *http.Request, userdata UserData) error {
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	if l.options.OutputFolder != "" {
		l.asyncqueue <- OutputData{data: reqdump, userdata: userdata}
	}

	if l.options.Verbose {
		gologger.Silentf(string(reqdump))
	}

	if l.options.OutputKafka != "" {
		split_arr := strings.Split(l.options.OutputKafka, "|")
		if len(split_arr) == 2 {
			addr := split_arr[0]
			topic := split_arr[1]
			msg2kafka(reqdump, userdata.id, addr, topic)
		} else {
			gologger.Printf("kafka module is invalid because of wrong configuration\r\n")
		}
	}

	return nil
}

func (l *Logger) LogResponse(resp *http.Response, userdata UserData) error {
	if resp == nil {
		return nil
	}
	respdump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	if l.options.OutputFolder != "" {
		l.asyncqueue <- OutputData{data: respdump, userdata: userdata}
	}

	if l.options.Verbose {
		gologger.Silentf(string(respdump))
	}

	if l.options.OutputKafka != "" {
		split_arr := strings.Split(l.options.OutputKafka, "|")
		if len(split_arr) == 2 {
			addr := split_arr[0]
			topic := split_arr[1]
			msg2kafka(respdump, userdata.id, addr, topic)
		} else {
			gologger.Printf("kafka module is invalid because of wrong configuration\r\n")
		}
	}

	return nil
}

func (l *Logger) Close() {
	close(l.asyncqueue)
}
