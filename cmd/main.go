package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/armosec/kubecop/pkg/ebpf"
	"github.com/armosec/kubecop/pkg/engine"
)

func main() {

	ebpfManager := ebpf.NewEbpfManager(60)
	ebpfManager.StartEventCollection()

	engine := engine.NewEngine()
	go engine.Start()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	log.Println("Shutting down...")

	ebpfManager.StopEventCollection()

	// Exit with success
	os.Exit(0)
}
