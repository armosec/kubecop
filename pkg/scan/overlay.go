package scan

import (
	"fmt"
	"log"
	"strings"

	"github.com/prometheus/procfs"
)

type Overlay struct {
	// UpperDir is the path to the upper directory of the overlay filesystem.
	UpperDir string
	// WorkDir is the path to the work directory of the overlay filesystem.
	WorkDir string
	// MergedDir is the path to the merged directory of the overlay filesystem.
	MergedDir string
	// LowerDir is the path to the lower directory of the overlay filesystem.
	LowerDir string
}

func GetOverlayLayer(path string, pid uint32) string {
	process, err := procfs.NewProc(int(pid))
	if err != nil {
		log.Printf("Error creating procfs for PID %d: %s\n", pid, err)
		return ""
	}

	// Get the overlay mount points for the process.
	overlay, err := getOverlayMountPoints(&process)
	if err != nil {
		log.Printf("Error getting overlay mount points for PID %d: %s\n", pid, err)
		return ""
	}

	// Check if the path is in one of the overlay mount points.
	if strings.HasPrefix(path, overlay.LowerDir) {
		return "lower"
	} else if strings.HasPrefix(path, overlay.UpperDir) {
		return "upper"
	} else if strings.HasPrefix(path, overlay.WorkDir) {
		return "work"
	} else if strings.HasPrefix(path, overlay.MergedDir) {
		return "merged"
	}

	return ""
}

func getOverlayMountPoints(process *procfs.Proc) (Overlay, error) {
	// Read the mount info for the process, and find the overlay mount point. (There should only be one?).
	if mounts, err := process.MountInfo(); err == nil {
		for _, mount := range mounts {
			if mount.FSType == "overlay" {
				// Return the merged directory.
				return Overlay{
					mount.SuperOptions["upperdir"],
					mount.SuperOptions["workdir"],
					strings.Replace(mount.SuperOptions["upperdir"], "diff", "merged", 1),
					mount.SuperOptions["lowerdir"],
				}, nil
			}
		}
	}

	return Overlay{}, fmt.Errorf("failed to get mount point for pid %d", process.PID)
}
