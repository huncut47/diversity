package web

import "minitwit/internal/models"

const latestKey = "latest"

func (app *App) GetLatest() int {
	var s models.AppState
	if err := app.DB.Where("key = ?", latestKey).First(&s).Error; err != nil {
		return 0
	}
	return int(s.Value)
}

func (app *App) SetLatest(v int) {
	// GREATEST ensures concurrent writes from multiple replicas only move forward.
	app.DB.Exec(`
          INSERT INTO app_state (key, value) VALUES (?, ?)
          ON CONFLICT (key) DO UPDATE SET value =
              CASE WHEN EXCLUDED.value > app_state.value
                   THEN EXCLUDED.value ELSE app_state.value END
  `, latestKey, int64(v))
}
