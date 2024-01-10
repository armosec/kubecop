package scan

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/prometheus/procfs"
)

type Overlay struct {
	// UpperDir is the path to the upper directory of the overlay filesystem.
	UpperDir string
	// WorkDir is the path to the work directory of the overlay filesystem.
	WorkDir string
	// MergedDir is the path to the merged directory of the overlay filesystem.
	MergedDir string
	// LowerDirs is the path to the lower directory of the overlay filesystem.
	LowerDirs []string
}

func GetOverlayLayer(path string, pid uint32) string {
	process, err := procfs.NewProc(int(pid))
	if err != nil {
		log.Infof("Error creating procfs for PID %d: %s\n", pid, err)
		return ""
	}

	// Get the overlay mount points for the process.
	overlay, err := getOverlayMountPoints(&process)
	if err != nil {
		log.Errorf("Error getting overlay mount points for PID %d: %s\n", pid, err)
		return ""
	}

	// Check if the path is in one of the overlay mount points.
	for _, lowerDir := range overlay.LowerDirs {
		if strings.HasPrefix(path, lowerDir) {
			return "lower"
		}
	}

	if strings.HasPrefix(path, overlay.UpperDir) {
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
					strings.Split(mount.SuperOptions["lowerdir"], ":"),
				}, nil
			}
		}
	}

	return Overlay{}, fmt.Errorf("failed to get mount point for pid %d", process.PID)
}
