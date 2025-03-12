package log_access

import (
	"fmt"
	"net"
	"os"

	"github.com/seaweedfs/seaweedfs/weed/glog"
	al "github.com/seaweedfs/seaweedfs/weed/pb/log_pb"
	"google.golang.org/protobuf/proto"
)

// PidToName retrieves the name of the process with the given PID.
// It reads the process name from the /proc filesystem on Unix-like systems.
//
// Parameters:
//
//	pid (int): The process ID.
//
// Returns:
//
//	string: The name of the process.
//	error: An error if the process name could not be read.
func pidToName(pid uint32) (string, error) {
	procPath := fmt.Sprintf("/proc/%d/comm", pid)
	comm, err := os.ReadFile(procPath)
	if err != nil {
		return "", err
	}
	return string(comm), nil
}

// SendLog sends an access log to the specified server.
//
// Parameters:
//   - server: The address of the server to send the log to.
//   - accessType: The type of access being logged.
//   - filePath: The path of the file being accessed.
//   - processId: The ID of the process accessing the file.
//
// The function retrieves the process name from the process ID and the file size from the file path.
// It then logs the access information and sends it to the server using a TCP connection.
func SendLog(
	server string,
	accessType al.AccessType,
	filePath string,
	fileSize uint64,
	processId uint32) {

	processName, err := pidToName(processId)
	if err != nil {
		glog.Warningf("Error getting process name: %v", err)
		processName = fmt.Sprintf("PID %d", processId)
	}

	glog.Warningf("Access log: %s %s %s %d %s", server, accessType, filePath, fileSize, processName)

	if server == "" {
		return
	}

	info := &al.AccessInfo{
		AccessType:  accessType,
		FilePath:    filePath,
		FileSize:    fileSize,
		ProcessName: processName,
		ProcessId:   processId,
	}
	out, err := proto.Marshal(info)
	if err != nil {
		glog.Warningf("Error marshalling access info: %v", err)
		return
	}

	conn, err := net.Dial("tcp", server)
	if err != nil {
		glog.Warningf("Error connecting to server: %s, %v", server, err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(out)
	if err != nil {
		glog.Warningf("Error sending access info: %v", err)
	}
}
