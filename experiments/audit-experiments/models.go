package auditexperiments

import "time"

type ObservationLog struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`
	Detail      string    `json:"detail"`
}

type ExperimentResult struct {
	ExperimentID   string                 `json:"experiment_id"`
	Type           string                 `json:"type"`
	TargetID       string                 `json:"target_id"`
	Status         string                 `json:"status"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	PreSnapshot    map[string]interface{} `json:"pre_snapshot"`
	PostSnapshot   map[string]interface{} `json:"post_snapshot"`
	SnapshotDiff   map[string]interface{} `json:"snapshot_diff"`
	Observations   []ObservationLog       `json:"observations"`
	Impact         string                 `json:"impact"`
	Restored       bool                   `json:"restored"`
}

type Experiment interface {
	Run() (*ExperimentResult, error)
}