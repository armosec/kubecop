package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	// If the environment variable WAIT_BEFORE_START is set, wait for X seconds
	// before starting
	if os.Getenv("WAIT_BEFORE_START") != "" {
		// Wait for X seconds (X is the value of the WAIT_BEFORE_START environment variable)
		if waitBeforeStart, err := time.ParseDuration(os.Getenv("WAIT_BEFORE_START")); err == nil {
			time.Sleep(waitBeforeStart)
		}
	}

	// Run all malicious behaviors
	runAllMaliciousBehaviors()

	// If the environment variable WAIT_FOR_SIGTERM is set, wait for SIGTERM
	// before exiting
	if os.Getenv("WAIT_FOR_SIGTERM") != "" {
		// Wait for SIGTERM
		sigterm := make(chan os.Signal, 1)
		signal.Notify(sigterm, syscall.SIGTERM)
		<-sigterm
	}
}

func runAllMaliciousBehaviors() error {
	// Download Kubectl binary (this should not be malicious if all is in the application profile)
	err := downloadKubectl()
	if err != nil {
		fmt.Printf("Failed to download kubectl: %v\n", err)
		return err
	}

	// Run the malicious behaviors

	fmt.Println("Running malicious behaviors...")

	// Trigger unexpected process launch (R0001)
	// Trigger exec binary not in base image (R1001)
	// Trigger unexpected service account use (R0006)
	// Trigger kubernetes client executed in container (R0007)
	// Run Kubectl get secrets by calling kubectl binary
	fmt.Println("Running kubectl get secrets...")
	output, err := runKubectl("./kubectl", "get", "secrets")
	if err != nil {
		fmt.Printf("Failed to run kubectl: %v\n", err)
	}
	fmt.Print(output)

	// Trigger unexpected file access (R0002)
	// Open a file for writing
	fmt.Println("Opening malicious.txt for writing...")
	file, err := os.OpenFile("malicious.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
	} else {
		// Write to the file
		_, err = file.WriteString("This is a malicious file\n")
		if err != nil {
			fmt.Printf("Failed to write to file: %v\n", err)
		}
		// Close the file
		err = file.Close()
		if err != nil {
			fmt.Printf("Failed to close file: %v\n", err)
		}
	}

	// Trigger crypto mining (R1003)
	// Open a file for writing in the name of known_hosts
	fmt.Println("Opening known_hosts for writing...")
	file, err = os.OpenFile("known_hosts", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
	} else {
		defer file.Close()
	}

	// Trigger unexpected DNS access (R0005)
	// Make an HTTP request
	fmt.Println("Making HTTP request to google.com...")
	_, err = http.Get("https://www.google.com")
	if err != nil {
		fmt.Printf("Failed to make HTTP request: %v\n", err)
	}

	// Trigger unexpected system call (R0003)
	// Trigger unshare system call (R1006)
	// Call unshare system call
	fmt.Println("Calling unshare system call...")
	_, _, err = syscall.Syscall(syscall.SYS_UNSHARE, syscall.CLONE_NEWUSER, 0, 0)
	if err != nil {
		fmt.Printf("Failed to call unshare system call: %v\n", err)
	}

	// Trigger unexpected capabilities (R0004)
	// Bind to a privileged port with a socket with HTTP server than close it
	fmt.Println("Binding to port 80...")
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Failed to bind to port 80: %v\n", err)
	} else {
		// Close the listener
		err = listener.Close()
		if err != nil {
			fmt.Printf("Failed to close listener: %v\n", err)
		}
	}

	// Trigger exec from malicious source (R1000)
	// Open kubectl as a file
	fmt.Println("Opening kubectl as a file...")
	file, err = os.Open("kubectl")
	if err != nil {
		fmt.Printf("Failed to open kubectl: %v\n", err)
	} else {
		// Get the the file descriptor
		fd := file.Fd()
		path := fmt.Sprintf("/proc/self/fd/%d", fd)
		// Fork the process
		switch child, _, _ := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0); child {
		case 0:
			// Call execve on the file descriptor
			fmt.Printf("Calling execve on %s...\n", path)
			err = syscall.Exec(path, []string{"kubectl", "get", "secrets"}, os.Environ())
			if err != nil {
				fmt.Printf("Failed to call execve on kubectl: %v\n", err)
			}
		case 1:
			fmt.Printf("Failed to fork process\n")
		default:
			// Wait for the child process to exit
			var status syscall.WaitStatus
			_, err = syscall.Wait4(int(child), &status, 0, nil)
			if err != nil {
				fmt.Printf("Failed to wait for child process: %v\n", err)
			}
		}
	}

	// Trigger load kernel module (R1002)
	// Load a kernel module (call insmod system call)
	fmt.Println("Loading kernel module...")
	_, _, err = syscall.Syscall(syscall.SYS_INIT_MODULE, 0, 0, 0)
	if err != nil {
		fmt.Printf("Failed to call init_module system call: %v\n", err)
	}

	// Trigger Exec from mount (R1004)
	// Copy the kubectl binary to /podmount
	fmt.Println("Copying kubectl to /podmount...")
	err = copyFile("kubectl", "/podmount/kubectl")
	if err != nil {
		fmt.Printf("Failed to copy kubectl to /podmount: %v\n", err)
	} else {
		// Call execve on the file
		fmt.Println("Calling kubectl on /podmount/kubectl...")

		out, err := runKubectl("/podmount/kubectl", "get", "secrets")
		if err != nil {
			fmt.Printf("Failed to call kubectl on /podmount/kubectl: %v\n", err)

		}
		if out != "" {
			fmt.Print(out)
		}
	}

	// Trigger crypto mining (R1007)
	// Do a TCP connect to stratum+tcp://xmr.pool.minergate.com:45700
	fmt.Println("Connecting to stratum+tcp://xmr.pool.minergate.com:45700...")
	conn, err := net.Dial("tcp", "xmr.pool.minergate.com:45700")
	if err != nil {
		fmt.Printf("Failed to connect to stratum+tcp://xmr.pool.minergate.com:45700: %v\n", err)
	} else {
		// Close the connection
		conn.Close()
	}

	return nil
}

// downloadFile downloads a file from the specified URL and saves it to the given filepath.
func downloadFile(filepath string, url string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to download file: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// downloadKubectl downloads the latest kubectl binary for the current platform.
func downloadKubectl() error {
	// Determine the OS and Architecture
	osName := runtime.GOOS
	arch := runtime.GOARCH

	fmt.Print("Downloading kubectl\n")

	url := fmt.Sprintf("https://dl.k8s.io/release/v1.28.4/bin/%s/%s/kubectl", osName, arch)

	// Print the URL
	fmt.Printf("Downloading kubectl from %s...\n", url)

	// Download the file
	err := downloadFile("kubectl", url)
	if err != nil {
		return err
	}

	// Make the kubectl binary executable
	err = os.Chmod("kubectl", 0755)
	if err != nil {
		return err
	}

	fmt.Println("kubectl downloaded successfully.")
	return nil
}

func runKubectl(path string, args ...string) (string, error) {
	// Create an *exec.Cmd
	cmd := exec.Command(path, args...)

	// Capture the output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run the command
	err := cmd.Run()
	if err != nil {
		return out.String(), err
	}

	return out.String(), nil
}

func copyFile(src, dst string) error {
	// Open the source file for reading
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Create the destination file for writing
	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	// Copy the contents of the source file to the destination file
	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}

	// Copy file permissions from source to destination
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	err = os.Chmod(dst, sourceInfo.Mode())
	if err != nil {
		return err
	}

	return nil
}
