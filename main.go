package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/sirupsen/logrus"
)

func main() {
	var packetFilter string
	flag.StringVar(&packetFilter, "extcap-capture-filter", "not port 22", "packet filter")

	var remoteAddress string
	flag.StringVar(&remoteAddress, "remote-address", "tcp://10.211.55.12:1234", "remote address")

	var fifo string
	flag.StringVar(&fifo, "fifo", "", "fifo path")

	var debug bool
	flag.BoolVar(&debug, "debug", false, "set verbosity level to debug")

	flag.BoolFunc("extcap-interfaces", "list extcap interfaces", func(s string) error {
		fmt.Fprint(os.Stdout, "extcap {version=1.0.0}\n")
		fmt.Fprint(os.Stdout, "interface {value=ig}{display=Inspektor Gadget (Daemon)}\n")
		fmt.Fprint(os.Stdout, "interface {value=ig-k8s}{display=Inspektor Gadget on Kubernetes}\n")
		os.Exit(0)
		return nil
	})

	var showConfig bool
	flag.BoolVar(&showConfig, "extcap-config", false, "show extcap configuration")

	var extcapInterface string
	flag.StringVar(&extcapInterface, "extcap-interface", "ig", "extcap interface")

	var capture bool
	flag.BoolVar(&capture, "capture", false, "start capture")

	var gadgetImage string
	flag.StringVar(&gadgetImage, "gadget-image", "tcpdump:latest", "gadget image")

	var snapLen int
	flag.IntVar(&snapLen, "snap-len", 65535, "snap length")

	var k8sNamespace string
	var k8sPodname string
	var k8sContainername string
	var k8sSelector string
	flag.StringVar(&k8sNamespace, "k8s-namespace", "", "k8s namespace")
	flag.StringVar(&k8sPodname, "k8s-podname", "", "k8s podname")
	flag.StringVar(&k8sContainername, "k8s-containername", "", "k8s container name")
	flag.StringVar(&k8sSelector, "k8s-selector", "", "k8s selector")

	var runtimeContainername string
	flag.StringVar(&runtimeContainername, "runtime-containername", "", "runtime container name")

	flag.Parse()

	if showConfig {
		switch extcapInterface {
		case "ig":
			fmt.Fprint(os.Stdout, "arg {number=20}{call=--remote-address}{display=Remote Address}{type=string}{default=tcp://10.211.55.12:1234}{group=Remote}\n")
			fallthrough
		case "ig-k8s":
			fmt.Fprint(os.Stdout, "arg {number=1}{call=--k8s-namespace}{display=Namespace}{type=string}{group=Kubernetes}\n")
			fmt.Fprint(os.Stdout, "arg {number=2}{call=--k8s-podname}{display=Pod Name}{type=string}{group=Kubernetes}\n")
			fmt.Fprint(os.Stdout, "arg {number=3}{call=--k8s-containername}{display=Container Name}{type=string}{group=Kubernetes}\n")
			fmt.Fprint(os.Stdout, "arg {number=4}{call=--k8s-selector}{display=Label Selector}{type=string}{group=Kubernetes}\n")
			fmt.Fprint(os.Stdout, "arg {number=5}{call=--runtime-containername}{display=Runtime Container Name}{type=string}{group=Containers}\n")
		}
		fmt.Fprint(os.Stdout, "arg {number=30}{call=--gadget-image}{display=Gadget Image}{type=string}{default=tcpdump:latest}{group=Gadget}\n")
		fmt.Fprint(os.Stdout, "arg {number=31}{call=--snap-len}{display=SnapLen}{type=integer}{range=0,65535}{default=65535}{group=Gadget}\n")
		fmt.Fprint(os.Stdout, "arg {number=32}{call=--debug}{display=Debug}{type=boolean}{group=Gadget}\n")
		os.Exit(0)
	}

	if capture {
		if extcapInterface == "" {
			os.Exit(0)
		}

		var f io.WriteCloser
		if fifo != "" {
			var err error
			f, err = os.OpenFile(fifo, os.O_WRONLY, os.ModeNamedPipe)
			if err != nil {
				panic(err)
			}
			defer f.Close()
		} else {
			f = os.Stdout
		}

		// PCAP-NG writer
		writer := simple.New("pcap-writer", simple.OnPreStart(func(gadgetCtx operators.GadgetContext) error {
			datasources := gadgetCtx.GetDataSources()
			ds, ok := datasources["packets"]
			if !ok {
				return errors.New("no packet datasource found")
			}

			// Check ds for compatiblity
			payloadField := ds.GetField(ds.Annotations()[clioperator.AnnotationPCAPPayload])
			if payloadField == nil {
				return fmt.Errorf("%s annotation not found", clioperator.AnnotationPCAPPayload)
			}

			// We need the raw timestamp, not the converted one; hardcoded for now
			timestampField := ds.GetField("timestamp_raw")
			if timestampField == nil {
				return fmt.Errorf("timestamp field not found")
			}
			lengthField := ds.GetField(ds.Annotations()[clioperator.AnnotationPCAPPacketLen])
			if lengthField == nil {
				return fmt.Errorf("length field not found")
			}

			procCommField := ds.GetField("proc.comm")

			// TODO:
			// Currently, each data packet carries all interface/enriched information with the payload;
			// optimally, we would create a special datasource for it and cache the sent information both
			// on sender and receiver to save bandwidth.

			// Find fields to be used for the interface key
			var interfaceKeyFields []datasource.FieldAccessor
			for _, f := range ds.Fields() {
				if v, ok := f.Annotations[clioperator.AnnotationPCAPInterfaceKey]; ok && v == "true" {
					acc := ds.GetField(f.FullName)
					if acc == nil {
						return fmt.Errorf("field %q not found", f.FullName)
					}
					interfaceKeyFields = append(interfaceKeyFields, acc)
				}
			}

			// Find fields to be used for the interface variables; these variables will become
			// part of the interface description and can be decoded using scripts in WireShark, for
			// example. TODO: also add this functionality on a packet level.
			var interfaceVarFns []func(datasource.Data, *strings.Builder)
			for _, f := range ds.Fields() {
				if v, ok := f.Annotations[clioperator.AnnotationPCAPInterfaceVar]; ok {
					acc := ds.GetField(f.FullName)
					if acc == nil {
						return fmt.Errorf("field %q not found", f.FullName)
					}
					if acc.Type() != api.Kind_String && acc.Type() != api.Kind_CString {
						return fmt.Errorf("field %q cannot be used as interface variable; currently, only string fields are supported", f.FullName)
					}
					interfaceVarFns = append(interfaceVarFns, func(data datasource.Data, sb *strings.Builder) {
						str, err := acc.String(data)
						if err != nil {
							return
						}
						sb.WriteString(v)
						sb.WriteByte('=')
						sb.WriteString(url.QueryEscape(str))
					})
					interfaceKeyFields = append(interfaceKeyFields, acc)
				}
			}

			var mu sync.Mutex

			wr, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
			if err != nil {
				return fmt.Errorf("creating pcapgo.NgWriter: %w", err)
			}

			interfaces := make(map[string]int)

			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				mu.Lock()
				defer mu.Unlock()

				var key strings.Builder
				for _, f := range interfaceKeyFields {
					key.Write(f.Get(data))
					key.WriteByte(':') // Delimiter
				}
				ifIndex := key.String()

				ts, _ := timestampField.Uint64(data)
				payload, _ := payloadField.Bytes(data)
				length, _ := lengthField.Uint32(data)

				pcapInterface, ok := interfaces[ifIndex]
				if !ok {
					// Build description for interface
					var description strings.Builder
					for i, f := range interfaceVarFns {
						if i > 0 {
							description.WriteByte(';')
						}
						f(data, &description)
					}

					newInterface := pcapgo.NgInterface{
						Name:        "virtual", // TODO: get from host
						Description: description.String(),
						OS:          runtime.GOOS, // TODO: get from host
						LinkType:    layers.LinkTypeEthernet,
					}
					newIndex, err := wr.AddInterface(newInterface)
					if err != nil {
						return err
					}
					interfaces[ifIndex] = newIndex
					pcapInterface = newIndex
				}

				options := pcapgo.NgPacketOptions{}

				if procCommField != nil {
					comm, _ := procCommField.String(data)
					options.Comments = append(options.Comments, "proc.comm="+comm)
				}

				err = wr.WritePacketWithOptions(gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, int64(time.Duration(ts))),
					InterfaceIndex: pcapInterface,
					CaptureLength:  len(payload),
					Length:         int(length),
				}, payload, options)
				if err != nil {
					gadgetCtx.Logger().Warnf("failed to write packet: %v", err)
					return nil
				}

				// need to make sure this gets written before returning buffers
				wr.Flush()
				return nil
			}, 10000)
			return nil
		}))

		var runtime *grpcruntime.Runtime
		var globalParams *params.Params
		var rtParams *params.Params

		pv := api.ParamValues{
			"operator.oci.ebpf.pf":      packetFilter,
			"operator.oci.ebpf.snaplen": fmt.Sprintf("%d", snapLen),
		}

		switch extcapInterface {
		default:
			fmt.Println("unsupported extcap interface")
			os.Exit(1)
		case "ig":
			runtime = grpcruntime.New()
			globalParams = runtime.GlobalParamDescs().ToParams()
			globalParams.Set("remote-address", remoteAddress)
			rtParams = runtime.ParamDescs().ToParams()
			if k8sNamespace != "" {
				pv["operator.LocalManager.k8s-namespace"] = k8sNamespace
			}
			if k8sContainername != "" {
				pv["operator.LocalManager.k8s-containername"] = k8sContainername
			}
			if k8sPodname != "" {
				pv["operator.LocalManager.k8s-podname"] = k8sPodname
			}
			if k8sSelector != "" {
				pv["operator.LocalManager.k8s-selector"] = k8sSelector
			}
			if runtimeContainername != "" {
				pv["operator.LocalManager.runtime-containername"] = runtimeContainername
			}
		case "ig-k8s":
			runtime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
			globalParams = runtime.GlobalParamDescs().ToParams()
			rtParams = runtime.ParamDescs().ToParams()

			config, err := utils.KubernetesConfigFlags.ToRESTConfig()
			if err != nil {
				panic(fmt.Errorf("Creating RESTConfig: %w", err))
			}
			runtime.SetRestConfig(config)

			if k8sNamespace != "" {
				pv["operator.KubeManager.k8s-namespace"] = k8sNamespace
			}
			if k8sContainername != "" {
				pv["operator.KubeManager.k8s-containername"] = k8sContainername
			}
			if k8sPodname != "" {
				pv["operator.KubeManager.k8s-podname"] = k8sPodname
			}
			if k8sSelector != "" {
				pv["operator.KubeManager.k8s-selector"] = k8sSelector
			}
			if runtimeContainername != "" {
				pv["operator.KubeManager.runtime-containername"] = runtimeContainername
			}
		}

		err := runtime.Init(globalParams)
		if err != nil {
			panic(err)
		}

		// Run tcpdump gadget
		var l logger.Logger
		if debug {
			f, err := os.CreateTemp(os.TempDir(), "ig-extcap")
			if err != nil {
				panic(err)
			}
			l = logrus.StandardLogger()
			logrus.SetOutput(f)
			l.SetLevel(logger.DebugLevel)
			l.Infof("started with arguments %v", os.Args)
		} else {
			l = logger.DefaultLogger()
			l.SetLevel(logger.FatalLevel)
		}

		gadgetCtx := gadgetcontext.New(context.Background(), gadgetImage, gadgetcontext.WithLogger(l), gadgetcontext.WithDataOperators(writer))
		err = runtime.RunGadget(gadgetCtx, rtParams, pv)
		if err != nil {
			os.Stderr.Write([]byte(err.Error()))
		}
	}
}
