package auditexperiments

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func RunExperiment(exp Experiment, outputDir string) error {
	result, err := exp.Run()
	if err != nil {
		return fmt.Errorf("experiment failed: %w", err)
	}

	// Print summary
	fmt.Printf("\n[%s] %s\n", result.Status, result.Type)
	fmt.Printf("Target:   %s\n", result.TargetID)
	fmt.Printf("Duration: %s\n", result.EndTime.Sub(result.StartTime).Round(time.Second))
	fmt.Printf("Restored: %v\n", result.Restored)
	fmt.Printf("Impact:   %s\n\n", result.Impact)
	for _, obs := range result.Observations {
		fmt.Printf("  [%s] %s: %s\n", obs.Timestamp.Format("15:04:05"), obs.Event, obs.Detail)
	}

	// Save to file
	if outputDir != "" {
		path := fmt.Sprintf("%s/%s_%s.json", outputDir, result.Type, result.ExperimentID[:8])
		data, _ := json.MarshalIndent(result, "", "  ")
		os.WriteFile(path, data, 0644)
		fmt.Printf("\nSaved to %s\n", path)
	}

	return nil
}