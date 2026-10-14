package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	_ = wails.Run(&options.App{
		Title:            "capx · 抓包桌面端",
		Width:            1280,
		Height:           820,
		MinWidth:         960,
		MinHeight:        600,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 244, G: 246, B: 248, A: 1},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
	})
}
