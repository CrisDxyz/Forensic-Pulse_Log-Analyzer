#Requires AutoHotkey v2.0
#SingleInstance Force ; Ensure only one instance runs
;#Include Dim_Echo_Box.ahk ; My debugger https://github.com/CrisDxyz/Dim_Echo_Box

/*
===============================================================================
                         Forensic Pulse Log Analyzer
===============================================================================

Version: 0.9.1
Created by: CrisDxyz
Date: Today
License: BSD 3-Clause License
Github: https://github.com/CrisDxyz/Forensic-Pulse_Log-Analyzer

===============================================================
                      Description & Usage:
===============================================================

  Forensic Pulse is an enterprise-grade cybersecurity log analyzer tool
  written in AutoHotkey v2. It parses specific log formats, primarily
  focusing on SSH server logs (secure.log / auth.log), to detect potential
  security incidents.

Key Features:
  - Parses SSH logs to extract relevant event data (timestamps, IPs, usernames).
  - Detects and displays potential brute-force attacks based on IP address, 
    attempt threshold, and time window using "config.ini" file parameters.
  - Tracks failed login attempts per username across all file.
  - Provides a GUI with progress updates and results displayed in sortable lists.
  - Offers two analysis modes via a dropdown menu:
    * Detailed Analysis: Includes DEBUG-level logs in "_Execution.log" showing
      parsing steps and detailed processing information. Useful for debugging
      log formats, script logic or checking the quality of your log file*.
	  *[DETAILS] log commented initially, too much verbose for "casual/quick" use.
    * Quick Analysis: Provides INFO, WARNING, and ERROR logs only, along with a
      summary of parsing statistics (lines processed, parse failures, missing IPs).
      Faster and produces a cleaner log for standard runs.
  - Generates a timestamped text report (`brute_force_report_YYYYMMDD_HHMMSS.txt`)
    summarizing detected brute-force incidents and top failing usernames.
  - Able to handle window resizes like a champ.
  - Black Theme by default.

Usage:
  1. Configure Settings: Update the "LogFilePath" within the config.ini file (backup below).
     By default, it will analyze "secure.log" file in the same directory.
  2. Run the script "Forensic_Pulse-Log_Analyzer.ahk" file using AutoHotkey v2.
  2. [Alternative] Run the release Forensic Pulse Log Analyzer.exe version.
  3. Select analysis mode: (Detailed/Quick) from the dropdown.
  4. Click "Start Analysis".
  5. View results: Displayed in GUI ListViews and the generated text report.
     (named according to the 'OutputReportPath' setting in config.ini + timestamp)
  6. [Optional] Check "_Execution.log" for operational details or errors.
     This file captures logs according the following levels:

Log Levels:
  [INFO]    - General operational steps, summaries, completion messages.
  [WARNING] - Non-critical issues encountered (e.g., timestamp conversion error).
  [ERROR]   - Critical errors preventing successful completion or causing issues.
  [DEBUG]   - Detailed step-by-step processing information (only logged in
              "Detailed Analysis" mode).

===============================================================
                Credits and Acknowledgments:
===============================================================
- Concept and Development: CrisDxyz (Me)
- Google cybersecurity 2024 course for "secure.log" files and initial idea.
- "SSH.log" file extracted from https://github.com/logpai/loghub
- "auth.log" file extracted from https://www.secrepo.com/

===============================================================
                   To do/future plans/ideas:
===============================================================
- Add Help menu with usage info and about info.
- Move header info to dedicated files and use header to point to them.
- Add tabs or file selection dialog to analyse different log files easily.
- Implement analysis for other attack patterns (e.g., port scanning, specific exploits).
- Support additional log file formats (e.g., web server logs, Windows Event Logs).
- Add options for configuring thresholds and patterns via the GUI.
- Implement detection for other types of security events beyond brute-force
    (e.g., specific exploit attempts, policy violations).
- Add report import and export options (e.g., CSV, JSON).
- Other general code improvements like adding .sort()'s.

===============================================================
                          Disclaimer:
===============================================================
This tool is provided "as is," without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. 

The analysis performed by this tool is based on predefined patterns and
thresholds. It may produce false positives or fail to detect certain
malicious activities (false negatives) depending of the log used and configuration.
Findings should always be correlated with other security tools
and manual investigation where appropriate.

In no event shall the authors or copyright holders be liable for any claim,
damages, or other liability, whether in an action of contract, tort, or
otherwise, arising from, out of, or in connection with the software or the
use or other dealings in the software. Use at your own risk.

===============================================================

===============================================================================
*/

; ==============================================================================
;                  Forensic Pulse Log Analyzer Configuration
; ==============================================================================
; Description: Configuration settings for the log analysis script.
; ==============================================================================

; Default configuration
CONFIG := Map(
    "LogFilePath", A_ScriptDir "\secure.log", ; <<< --- !!! UPDATE THIS PATH WITH YOUR FILE !!!
    "OutputReportPath", A_ScriptDir "\brute_force_report_",
    "ScriptLogPath", A_ScriptDir "\Forensic_Pulse-Log_Analyzer_Execution.log",
    "BruteForceThreshold", 5,
    "TimeWindowSeconds", 300,
    "FailedLoginPattern", "i)(Failed password for|Invalid user)",
    "IPAddressPattern", "from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    "TimestampPattern", "^(?:(?:(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}:\d{2}:\d{2}))|(?:(\d{4})-(\d{2})-(\d{2})\s+(\d{2}:\d{2}:\d{2})))",
	"UsernameExtractionPattern", "i)(?:Failed password for\s+(?:invalid user\s+)?|Invalid user\s+)(\S+)",
    "UpdateIntervalLines", 1000, ; Update progress bar every n lines
    "GuiPadding", 10,
    "GuiButtonAreaHeight", 40,
	"GuiMinWidth", 500,
    "GuiMinHeight", 350,
	"DefaultVerbosityLevel", 4 ; 4=Detailed, 3=Quick
)

CONFIG := LoadConfigFromFile(A_ScriptDir "\config.ini")

/*
; ------------------------------------------------------------------------------
; Backup: config.ini file
; Description:
;	Original default contents of "config.ini" file below that are read by LoadConfigFromFile func.
;   To use it, just create a .txt file, name it "config.ini" and paste/modify the cofiguration content inside.
; ------------------------------------------------------------------------------

; Configuration for Forensic Pulse Log Analyzer Script:
; Lines starting with ; are comments and are ignored.
; Blank lines are also ignored.

; --- File Paths ---
; LogFilePath is the file the script analyses. 
; Replace with absolute paths or paths relative to the script directory.
; A_ScriptDir will be prepended automatically by the script if not absolute.
; Example: LogFilePath=.\my_auths.log
LogFilePath=.\secure.log
OutputReportPath=.\brute_force_report_
ScriptLogPath=.\Forensic_Pulse-Log_Analyzer_Execution.log

; --- Analysis Parameters ---
BruteForceThreshold=5
TimeWindowSeconds=300

; --- Regular Expressions (Use AHK v2 syntax) ---
FailedLoginPattern=i)(Failed password for|Invalid user)
IPAddressPattern=from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
TimestampPattern=^(?:(?:(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}:\d{2}:\d{2}))|(?:(\d{4})-(\d{2})-(\d{2})\s+(\d{2}:\d{2}:\d{2})))
UsernameExtractionPattern=i)(?:Failed password for\s+(?:invalid user\s+)?|Invalid user\s+)(\S+)

; --- Performance / GUI ---
UpdateIntervalLines=1000
GuiPadding=10
GuiButtonAreaHeight=40
GuiMinWidth=500
GuiMinHeight=350

; --- Logging ---
; 4 = Detailed (Includes DEBUG messages)
; 3 = Quick (INFO, WARN, ERROR only)
DefaultVerbosityLevel=4

*/

; ------------------------------------------------------------------------------
; Function: LoadConfigFromFile
; Description:
;	Loads configuration settings from config.ini file.
; 	Parses file reading Key=Value pairs, ignoring comments (starting with ';') and blank lines.
; 	Provides default values for settings not found or if the file is missing.
; 	Attempts to convert known numeric settings to Integers.
;
; Parameters: configFilePath {String} The full path to the configuration file (e.g., "config.ini").
; Returns: loadedConfig {Map} A Map object containing the configuration settings. Returns default config if file not found.
; ------------------------------------------------------------------------------

LoadConfigFromFile(configFilePath) {
    ; --- Define Default Configuration ---
    local defaultConfig := CONFIG

    ; Start with defaults, file will override it
    local loadedConfig := defaultConfig.Clone()
    local fileObject

    LogMessage("Attempting to load configuration from: " configFilePath, "INFO")

    if not FileExist(configFilePath) {
        LogMessage("Configuration file not found. Using default settings.", "WARN")
        return defaultConfig
    }
	
    try {
        fileObject := FileOpen(configFilePath, "r", "UTF-8")
        if not IsObject(fileObject) {
            throw Error("Failed to open configuration file for reading.")
        }

        local lineNumber := 0
        while not fileObject.AtEOF {
            lineNumber++
            local line := Trim(fileObject.ReadLine())
			
            ; Skip blank lines and comments
            if (line = "" or SubStr(line, 1, 1) = ";") {
                continue
            }

            ; Find the first '=' separator
            local separatorPos := InStr(line, "=")
            if (separatorPos = 0) {
                LogMessage("Skipping malformed line " lineNumber " in config file (no '=' found): " line, "WARN")
                continue
            }

            ; Extract key and value, trim whitespace
            local key := Trim(SubStr(line, 1, separatorPos - 1))
            local value := Trim(SubStr(line, separatorPos + 1))

            ; Check if the key is a known/expected key
            if defaultConfig.Has(key) {
                ; Store the value from the file, overriding the default
                loadedConfig[key] := value
                LogMessage("Loaded config: " key " = " value, "INFO")
            } else {
                LogMessage("Ignoring unknown key '" key "' found on line " lineNumber " in config file.", "WARN")
            }
        }

    } catch Error as e {
        LogMessage("Error reading configuration file '" configFilePath "': " e.Message ". Using default settings.", "ERROR")
        return defaultConfig
    } finally {
        if IsObject(fileObject) {
            fileObject.Close()
        }
    }

    ; --- Post-Processing: Convert known numeric values ---
    local numericKeys := ["BruteForceThreshold", "TimeWindowSeconds", "UpdateIntervalLines",
                          "GuiPadding", "GuiButtonAreaHeight", "GuiMinWidth", "GuiMinHeight",
                          "DefaultVerbosityLevel"]

    for key in numericKeys {
        if loadedConfig.Has(key) {
            local stringValue := loadedConfig[key]
            try {
                ; Attempt to convert to integer
                loadedConfig[key] := Integer(stringValue)
            } catch ValueError {
                LogMessage("Invalid numeric value '" stringValue "' for key '" key "' in config file. Using default value: " defaultConfig[key], "WARN")
                ; Revert to the default numeric value if conversion fails
                loadedConfig[key] := defaultConfig[key]
            }
        }
    }

    LogMessage("Configuration loaded successfully from file config.ini", "INFO")
    return loadedConfig
}

; ==============================================================================
;                                Entry Point & GUI Setup
; ==============================================================================

/*
; ------------------------------------------------------------------------------
; Function: Main
; Description: Forensic Pulse Log Analyzer GUI:
;    Contains: Path text, progress bar.
;        Incidents and top failing users Listviews.
;        Detailed and Quick analysis verbose options to log on execution.log file.
;        Buttons to start analysis and close the script.
;    Handler lists: 
;        StartAnalysisHandler to start file analysis.
;        Supports resize via ResizeHandler and HandleMinMaxInfoMessage.
;        ListViewDoubleClickHandler to define what happens when user double clicks listview.
;        GuiCloseHandler to define what heppens when user clicks close button.
; ------------------------------------------------------------------------------     
*/

Main()

Main() {
    LogMessage("Script started. Initializing GUI.")

    local analyzerGui := Gui("+Resize", "Forensic Pulse - Log Analyzer")
    analyzerGui.MarginX := CONFIG["GuiPadding"]
    analyzerGui.MarginY := CONFIG["GuiPadding"]
	WM_GETMINMAXINFO := 0x0024
	TargetGuiHwnd := 0 ; Will store HWND of the main GUI for the OnMessage handler
	
	analyzerGui.BackColor := "101010"
    analyzerGui.SetFont("s8 cWhite q5 bold", "Consolas") ; Verdana also looks good
	
    ; --- Top Controls ---
    analyzerGui.statusText := analyzerGui.Add("Text", "w780 h28", "Log File to Analyze: " CONFIG["LogFilePath"])
    analyzerGui.progressBar := analyzerGui.Add("Progress", "w780 h20 y+5 Range0-100", 0)

    ; --- Text ---
    analyzerGui.Add("Text", "xs+10 y+5", "Detected Potential Incidents (by IP):") ; No variable assign since doesnt need resize or any manipulation
    analyzerGui.topfailusers := analyzerGui.Add("Text", "xp+600 yp", "Top Failing Usernames (Overall):")

    ; --- Possible Bruteforce Incidents ListView (Left Side) ---
    analyzerGui.bruteForceListView := analyzerGui.Add("ListView", "+LV0x10000 Background404040 xs w550 h300 y+2 Grid AltSubmit -Multi", 
													 ["IP Address", "Attempts", "Users Tried", "Window Start", "Window End", "Win Duration(s)", "Overall First", "Overall Last", "Overall Duration(s)"])
    analyzerGui.bruteForceListView.ModifyCol(1, "110")                ; IP Address
    analyzerGui.bruteForceListView.ModifyCol(2, "75 Integer Center")  ; Total Attempts
    analyzerGui.bruteForceListView.ModifyCol(3, "120")                ; Users Tried (Text)
    analyzerGui.bruteForceListView.ModifyCol(4, "130")                ; Window Start
    analyzerGui.bruteForceListView.ModifyCol(5, "130")                ; Window End
    analyzerGui.bruteForceListView.ModifyCol(6, "80 Integer Center")  ; Window Duration
    analyzerGui.bruteForceListView.ModifyCol(7, "130")                ; Overall First
    analyzerGui.bruteForceListView.ModifyCol(8, "130")                ; Overall Last
    analyzerGui.bruteForceListView.ModifyCol(9, "90 Integer Center")  ; Overall Duration

    ; --- Top Failing Usernames ListView (Right Side) ---
    analyzerGui.topUsersListView := analyzerGui.Add("ListView", "Background404040 x+20 yp w210 h300 Grid AltSubmit -Multi", ["Username", "Total Failed Attempts"])
    analyzerGui.topUsersListView.ModifyCol(1, "125") ; Username
    analyzerGui.topUsersListView.ModifyCol(2, "80 Integer Center") ; Total Failed Attempts

	; --- Analyzer Execution Log Verbosity Dropdown ---
    analyzerGui.verbosityDropdown := analyzerGui.Add("DropDownList", "+LV0x10000 xs+5 y+45 w150 Choose1", ["Detailed Analysis", "Quick Analysis"])
    analyzerGui.verbosityDropdown.Text := "Detailed Analysis" ; Set default selection
	
    ; --- Buttons ---
    analyzerGui.startButton := analyzerGui.Add("Button", "xs y+1 w100 h25 Default", "Start Analysis")
    analyzerGui.startButton.OnEvent("Click", StartAnalysisHandler)
    analyzerGui.closeButton := analyzerGui.Add("Button", "x+10 yp w100 h25", "Close")
    analyzerGui.closeButton.OnEvent("Click", GuiCloseHandler)
	
	; --- Events ---
    analyzerGui.OnEvent("Close", GuiCloseHandler)
    analyzerGui.OnEvent("Size", ResizeHandler)
	analyzerGui.bruteForceListView.OnEvent("DoubleClick", ListViewDoubleClickHandler)
	
	; Top dark frame
	SetDarkWindowFrame(analyzerGui)
	
	global TargetGuiHwnd := analyzerGui.Hwnd
    OnMessage(WM_GETMINMAXINFO, HandleMinMaxInfoMessage) ; Register the handler
	
    analyzerGui.Show("w820 h500")
    Return
}

; Dark mode window frame handler
; Credits of black windows frame to u/plankoe
SetDarkWindowFrame(hwnd, boolEnable := 1) {
    hwnd := WinExist(hwnd)
    if VerCompare(A_OSVersion, "10.0.17763") >= 0
        attr := 19
    if VerCompare(A_OSVersion, "10.0.18985") >= 0
        attr := 20
    DllCall("dwmapi\DwmSetWindowAttribute", "ptr", hwnd, "int", attr, "int*", boolEnable, "int", 4)
}

; ==============================================================================
;                                GUI Event Handlers
; ==============================================================================

; ------------------------------------------------------------------------------
; Handler: StartAnalysisHandler
; Description: Triggered when the "Start Analysis" button is clicked.
;
; Parameters:
;   btn {object} The control object that triggered the event (the button).
;   guiObj {object} The Gui object itself (passed automatically by OnEvent).
; ------------------------------------------------------------------------------

StartAnalysisHandler(btn, guiObj, *) {
    LogMessage("Analysis started by user.")
	
	; --- Disable start button --- 
	;guiObj.startButton.Disable() ; maybe will add this later to limit user from spamming the button

    ; --- Prepare GUI for Processing (Access controls via guiObj) ---
	guiObj := btn.Gui
    guiObj.progressBar.Value := 0
    guiObj.statusText.Value := "Initializing analysis..."
    guiObj.bruteForceListView.Delete()
	guiObj.topUsersListView.Delete()

    Sleep(50)

    ; --- Initialize Data Structures ---
    ipDataMap := Map()
    bruteForceResults := []
	usernameFailureCounts := Map()
    local success := true

    ; --- Determine Selected Verbosity Level ---
    selectedVerbosityText := guiObj.verbosityDropdown.Text
    currentVerbosityLevel := (selectedVerbosityText = "Quick Analysis") ? 3 : 4 ; 3=Quick, 4=Detailed
    LogMessage("Verbosity level set to: " currentVerbosityLevel " (" selectedVerbosityText ")", "INFO", currentVerbosityLevel)
	
    try {
        guiObj.statusText.Value := "Processing log file: " CONFIG["LogFilePath"] "..."
        if not ProcessLogFile(CONFIG["LogFilePath"], ipDataMap, usernameFailureCounts, guiObj, currentVerbosityLevel) {
            throw Error("Log file processing failed. See script log for details.")
        }
		
		LogMessage("StartAnalysisHandler: Immediately after ProcessLogFile returned. ipDataMap.Count = " ipDataMap.Count, "DEBUG", currentVerbosityLevel)
		
        guiObj.progressBar.Value := 100
        guiObj.statusText.Value := "Log processing complete. Analyzing data..."
        LogMessage("Log file processing completed via GUI.", "INFO", currentVerbosityLevel)
        LogMessage("Data check: Found " ipDataMap.Count " unique IPs in ipDataMap.", "INFO", currentVerbosityLevel)
        Sleep(50)

        bruteForceResults := AnalyzeBruteForceAttempts(ipDataMap, CONFIG["BruteForceThreshold"], CONFIG["TimeWindowSeconds"])
        LogMessage("Brute-force analysis completed. Found " bruteForceResults.Length " potential incidents.", "INFO", currentVerbosityLevel)
        guiObj.statusText.Value := "Analysis complete. Generating report..."
        Sleep(50)

        ; Call the report function
        if not GenerateReport(CONFIG["OutputReportPath"] . FormatTime(,"yyyyMMdd_HHmmss") ".txt", bruteForceResults, usernameFailureCounts, guiObj, currentVerbosityLevel) {
             LogMessage("Report generation step completed, but failed to write report file.", "WARNING", currentVerbosityLevel)
        } else {
             LogMessage("Report generated successfully: " CONFIG["OutputReportPath"] . FormatTime(,"yyyyMMdd_HHmmss") ".txt", "INFO", currentVerbosityLevel)
        }

        if (bruteForceResults.Length > 0 || usernameFailureCounts.Count > 0) {
             guiObj.statusText.Value := "Analysis complete. Found " bruteForceResults.Length " potential incidents. " usernameFailureCounts.Count " failing users.`nReport saved to: " CONFIG["OutputReportPath"] . FormatTime(,"yyyyMMdd_HHmmss") ".txt"
        } else {
             guiObj.statusText.Value := "Analysis complete. No incidents or potential brute force attacks detected meeting the configuration criteria."
        }

    } catch Error as e {
        success := false
        local errorMessage := "ERROR during analysis: " e.Message " (Line: " e.Line ")"
        LogMessage(errorMessage, "ERROR", currentVerbosityLevel)
        try {
		guiObj.statusText.Value := errorMessage 
		} catch { ; Update status if possible
		MsgBox(errorMessage, "Log Analyzer Error", 16)
		}
    } finally {
        ; --- Re-enable Button ---
        try {
		;guiObj.startButton.Enable()
		LogMessage("Analysis process finished.", "INFO", currentVerbosityLevel)
		} catch {
        LogMessage("Analysis process finished.", "INFO", currentVerbosityLevel)
		}
    }
}

; ------------------------------------------------------------------------------
; Handler: GuiCloseHandler
; Description: Called when the GUI is closed (X button or Close button).
; ------------------------------------------------------------------------------
; *todo: add echobox exit later
GuiCloseHandler(*) {
    LogMessage("GUI closed by user. Exiting script.")
    ExitApp()
}

; ------------------------------------------------------------------------------
; Handler: ResizeHandler
; Description: Handles resizing of the GUI window to adjust control sizes dynamically.
;
; Parameters:
;   guiObj {object} The Gui itself.
;   MinMax {int} Indicates minimizing (-1), maximizing (1), restoring (0), or resizing.
;   Width {int} New client area width.
;   Height {int} New client area height.
; ------------------------------------------------------------------------------

ResizeHandler(guiObj, MinMax, Width, Height) {
    if (MinMax = -1) { ; Window is minimized, do nothing
        return
    }
	
	minWidth := CONFIG["GuiMinWidth"]
	minHeight := CONFIG["GuiMinHeight"]

    ; --- Validation: Ensure all controls exist ---
    if not (IsObject(guiObj)
            && IsObject(guiObj.statusText) && guiObj.statusText.Hwnd
            && IsObject(guiObj.progressBar) && guiObj.progressBar.Hwnd
            && IsObject(guiObj.bruteForceListView) && guiObj.bruteForceListView.Hwnd
            && IsObject(guiObj.topUsersListView) && guiObj.topUsersListView.Hwnd ; Added check
			&& IsObject(guiObj.verbosityDropdown) && guiObj.verbosityDropdown.Hwnd
            && IsObject(guiObj.startButton) && guiObj.startButton.Hwnd
            && IsObject(guiObj.closeButton) && guiObj.closeButton.Hwnd) {
        LogMessage("ResizeHandler: Skipping resize - controls/HWNDs missing.", "WARNING")
        return
    }

    local padding := CONFIG["GuiPadding"]
    local buttonAreaHeight := CONFIG["GuiButtonAreaHeight"]
    local minLvWidth := 100 ; Minimum width for listviews
    local minLvHeight := 50 ; Minimum height for listviews

    try {
        ; --- Gui dimensions ---
        local availableWidth := Width - padding * 2
        local buttonTopY := Height - buttonAreaHeight
		
		; --- Min & max width ---
        if (availableWidth < 150) {
			availableWidth := 150
		}
        if (availableWidth > 1900) {
			availableWidth := 1900
		}

        ; ---  Min & max first listview height ---
        local listViewHeight := buttonTopY - 130
        if (listViewHeight < 150) {
			listViewHeight := 150
		}
        if (listViewHeight > 875) {
			listViewHeight := 875
		}

        ; --- Position and Size the ListViews ---
		; Enforce minimum from CONFIG
        local userLvFixedWidth := 210
        local bfLvWidth := availableWidth - userLvFixedWidth - padding
        if (bfLvWidth < minLvWidth) {
			bfLvWidth := minLvWidth
		}

        local userLvX := padding + bfLvWidth + padding
        local userLvY := padding + 75
        local userLvWidthActual := Width - userLvX - padding ; Calculate width based on remaining space
        if (userLvWidthActual < minLvWidth) {
			userLvWidthActual := minLvWidth
		}

        ; --- Move/Resize Top Controls and Buttons ---
		; Order is the same as GUI
        guiObj.statusText.Move(padding, padding, availableWidth)
        guiObj.progressBar.Move(padding, , availableWidth)
		guiObj.topfailusers.Move(availableWidth - 190, 70, availableWidth)
        guiObj.bruteForceListView.Move(padding, padding + 75, bfLvWidth, listViewHeight)
        guiObj.topUsersListView.Move(userLvX, userLvY, userLvWidthActual, listViewHeight)
		guiObj.verbosityDropdown.Move(padding, buttonTopY - 30)
        guiObj.startButton.Move(padding, buttonTopY)
        guiObj.closeButton.Move(padding + 110, buttonTopY)

		; Sometimes text glitches out, keeping the others just in case/until i make refresh handler.
        guiObj.statusText.Redraw()
        ;guiObj.progressBar.Redraw()
		;guiObj.topfailusers.Redraw()
        ;guiObj.bruteForceListView.Redraw()
        ;guiObj.topUsersListView.Redraw()
		;guiObj.verbosityDropdown.Redraw()
        ;guiObj.startButton.Redraw()
        ;guiObj.closeButton.Redraw()

    } catch Error as e {
        LogMessage("Error during GUI resize: " e.Message " (Line: " e.Line ")", "ERROR")
    }
}

/* ; *todo: create hotkey f5 later
F5::
{
	RefreshGUIHandler()
}

RefreshGUIHandler(guiObj){
	
	guiObj.statusText.Redraw()
	guiObj.progressBar.Redraw()
	guiObj.topfailusers.Redraw()
	guiObj.bruteForceListView.Redraw()
	guiObj.topUsersListView.Redraw()
	guiObj.verbosityDropdown.Redraw()
	guiObj.startButton.Redraw()
	guiObj.closeButton.Redraw()
}
*/

; ------------------------------------------------------------------------------
; Handler: HandleMinMaxInfoMessage
; Description: 
;   Handles the WM_GETMINMAXINFO windows message via OnMessage
;   Enforces minimum window size ONLY for the target (analyzer GUI) window.
; 
; Parameters:
;   wParam {Int} Not used for WM_GETMINMAXINFO.
;   lParam {Int} A pointer to a MINMAXINFO structure.
;   msg {Int} The message number (0x0024).
;   hwnd {Int} The HWND of the window receiving the message.
;
; Returns: {Int} Non-zero value (1 or "true") if handled for our target GUI, 0 otherwise.
; ------------------------------------------------------------------------------

HandleMinMaxInfoMessage(wParam, lParam, msg, hwnd) {
    global TargetGuiHwnd ; Access the variable holding our GUI's HWND from Main()

    ; --- Critical Check: Only process this message if it's for our specific GUI ---
    if (hwnd != TargetGuiHwnd) {
        return 0 ; Let other windows handle their messages normally
    }

    try {
        ; Get minimum dimensions from CONFIG
        local minWidth := CONFIG.Has("GuiMinWidth") ? CONFIG["GuiMinWidth"] : 500 ; Default fallback
        local minHeight := CONFIG.Has("GuiMinHeight") ? CONFIG["GuiMinHeight"] : 350 ; Default fallback

        ; MINMAXINFO structure offsets (standard Windows structure):
        ; ptMinTrackSize.x (Minimum tracking width): Offset 24
        ; ptMinTrackSize.y (Minimum tracking height): Offset 28
		
		; NumPut : Stores one or more numbers in binary format at the specified address+offset.
		; https://www.autohotkey.com/docs/v2/lib/NumPut.htm

        ; Write the minimum width to the structure
        NumPut("Int", minWidth, lParam + 24)

        ; Write the minimum height to the structure
        NumPut("Int", minHeight, lParam + 28)

        ; LogMessage("HandleMinMaxInfoMessage: Enforced MinWidth=" minWidth ", MinHeight=" minHeight " for HWND " hwnd, "DEBUG")

        return 1 ; Indicate message handled for our GUI

    } catch Error as e {
        LogMessage("Error in HandleMinMaxInfoMessage: " e.Message " (Line: " e.Line ")", "ERROR")
		LogMessage("HandleMinMaxInfoMessage: Enforced MinWidth=" minWidth ", MinHeight=" minHeight " for HWND " hwnd, "DEBUG")
        return 0
    }
}

; ------------------------------------------------------------------------------
; Handler: ListViewDoubleClickHandler
; Description: Action when a row in the ListView is double-clicked.
;
; Parameters:
;   lvCtrlObj {object} The ListView.
;   RowNumber {Int} The focused row number.
; ------------------------------------------------------------------------------

ListViewDoubleClickHandler(lvCtrlObj, RowNumber, *) {
    if (RowNumber == 0) {
        return
	}

    local ip := lvCtrlObj.GetText(RowNumber, 1)
    LogMessage("User double-clicked row " RowNumber " (IP: " ip ")", "DEBUG")
    MsgBox("You double-clicked on IP: " ip "`n(Copied to clipboard)", "Row " RowNumber, 64)
    A_ClipBoard := ip
}

; ==============================================================================
;                              Core Functions
; ==============================================================================

; ------------------------------------------------------------------------------
; Function: ProcessLogFile
; Description: Reads the specified log file line by line, parses relevant failure
;              events, populates data maps (ipDataMap, usernameFailureCounts),
;              updates the GUI progress bar, and logs summary/details based on verbosity.
;              *A few logs commented, too much info when doing detailed, but may change my opinion later.
;
; Parameters:
;   logFilePath {String} Full path to the log file.
;   ipDataMap {Map} To store IP-related parsed data {IP -> {Attempts, Timestamps, Usernames}}.
;   usernameFailureCounts {Map} To store username failure counts {Username -> Count}.
;   guiObj {object} The main application GUI object for updates on progress bar and text.
;   currentVerbosity {Int} The selected verbosity level (e.g., 3=Quick, 4=Detailed).
;
; Returns:
;   {bool} True if processing completed successfully (even if no data found), False on critical error (e.g., file open failure).
; ------------------------------------------------------------------------------

ProcessLogFile(logFilePath, ipDataMap, usernameFailureCounts, guiObj, currentVerbosity) {
    LogMessage("Entering ProcessLogFile", "DEBUG", currentVerbosity) ; Debug Entry Point Log

    ; --- Init Local Variables ---
    local fileObject            ; File handle
    local lineCount := 0        ; Total lines read from the file
    local parsedCount := 0      ; Lines successfully parsed as failure events
    local failedParseCount := 0 ; Lines matching failure pattern but failing critical parsing (timestamp/user)
    local missingIPCount := 0   ; Parsed failure events where IP address was not found
    local currentLine           ; Holds the content of the current log line being processed
    local parsedData            ; Holds the Map object returned by ParseLogLine, or False
    local totalSize             ; Total size of the log file in bytes for progress calculation
    local currentPos            ; Current byte position within the file during reading
    local percentage            ; Calculated progress percentage

    ; --- 1. Input Validation ---
    LogMessage("ProcessLogFile: Checking GUI objects...", "DEBUG", currentVerbosity)
    ; Ensure the GUI object and required controls (progress bar, status text) are valid before proceeding.
    if not IsObject(guiObj) or not IsObject(guiObj.progressBar) or not IsObject(guiObj.statusText)
    {
        LogMessage("ProcessLogFile called with invalid Gui object or missing controls.", "ERROR", currentVerbosity)
        Return false ; Cannot continue without GUI elements
    }

    LogMessage("ProcessLogFile: Clearing maps...", "DEBUG", currentVerbosity) ; Debug Map Clear
    ; Clear data maps from any previous runs before processing the new file.
    ipDataMap.Clear()
    usernameFailureCounts.Clear()

    ; --- 2. File Opening ---
    LogMessage("ProcessLogFile: Attempting to open file: " logFilePath, "DEBUG", currentVerbosity) ; Debug File Open Attempt
    try
    {
        ; Check if the specified log file exists.
        if not FileExist(logFilePath)
        {
            throw Error("Log file not found: " logFilePath)
        }

        ; Get the total size for progress bar calculation.
        totalSize := FileGetSize(logFilePath)
        ; Handle empty files to avoid division by zero later.
        if (totalSize <= 0)
        {
            totalSize := 1 ; Set to 1 byte to prevent errors, progress won't be accurate but won't crash.
        }

        ; Attempt to open the log file for reading with UTF-8 encoding.
        fileObject := FileOpen(logFilePath, "r", "UTF-8")
        ; Check if the file handle object was successfully created.
        if not IsObject(fileObject)
        {
            throw Error("Failed to open log file for reading: " logFilePath) ; Could be permissions, lock, etc.
        }
        LogMessage("ProcessLogFile: File opened successfully.", "DEBUG", currentVerbosity) ; Debug File Open Success Log
    }
    catch Error as e
    {
        ; Log any error encountered during file validation or opening.
        LogMessage("Error opening log file: " e.Message, "ERROR", currentVerbosity)
        ; Attempt to update the GUI status text with the error, catching potential GUI or user config errors.
        try {
			guiObj.statusText.Value := "Error opening log file: " e.Message
		} catch {
			; Return false (critical failure).
			return false
		}
    }

    ; --- 3. Main Processing Loop ---
    LogMessage("ProcessLogFile: Starting main processing loop.", "DEBUG", currentVerbosity) ; Debug Loop Start Log
    try
    {
        ; Loop through the file line by line until the end is reached (eof).
        while not fileObject.AtEOF
        {
            currentLine := fileObject.ReadLine() ; Read the next line
            lineCount++                          ; total line counter + 1

            ; Attempt to parse the current line, passing the verbosity level for conditional logging within ParseLogLine.
            parsedData := ParseLogLine(currentLine, currentVerbosity)

            ; Check if ParseLogLine returned a valid Map object (successful parsing).
            if IsObject(parsedData)
            {
                parsedCount++ ; Increment the count of successfully parsed failure events/incidents and store data
                local username := parsedData["Username"]
                local ip := parsedData["IP"]
                local timestamp := parsedData["Timestamp"]

                ;LogMessage("[DETAILS] Parsed Line " lineCount ": User='" username "', IP='" ip "'", "DEBUG", currentVerbosity) ; Debug Parsed Data

                ; --- Update Username Failure Counts ---
                ; Increment the count for this username in the overall failure {map}.
                if usernameFailureCounts.Has(username)
                {
                    usernameFailureCounts[username]++
                }
                else
                {
                    usernameFailureCounts[username] := 1 ; Initialize if first time getting this user
                }

                ; --- Update IP-based Data ---
                ; Only process IP-related data if an IP address was actually extracted (!null).
                if (ip != "")
                {
                    ;LogMessage("[DETAILS] IP Check Passed for IP: '" ip "'. Updating ipDataMap.", "DEBUG", currentVerbosity) ; Debug IP Found

                    ; Check if this IP is already in the ipDataMap.
                    if not ipDataMap.Has(ip)
                    {
                        ;LogMessage("[DETAILS] Creating new entry for IP: " ip, "DEBUG", currentVerbosity) ; Debug New IP Entry
                        ; If not, create a new nested map structure for this IP.
                        ipDataMap[ip] := Map("Attempts", 0, "Timestamps", [], "Usernames", Map())
                    }

                    ; Increment the total attempt count for this IP.
                    ipDataMap[ip]["Attempts"]++
                    ; Add the timestamp of this attempt to the IP's timestamp list.
                    ipDataMap[ip]["Timestamps"].Push(timestamp)

                    ; Update the count for the specific username tried from this IP.
                    local userMap := ipDataMap[ip]["Usernames"] ; Get reference to the nested username map
                    if userMap.Has(username)
                    {
                        userMap[username]++
                    }
                    else
                    {
                        userMap[username] := 1 ; Initialize if first attempt for this user from this IP
                    }
                    ;LogMessage("[DETAILS] Updated data for IP: " ip ". New Attempts: " ipDataMap[ip]['Attempts'], "DEBUG", currentVerbosity) ; Debug IP Data Update
                }
                else
                {
                    ; If IP was empty for this successfully parsed event, increment the missing IP counter.
                    missingIPCount++
                    ;LogMessage("[DETAILS] IP Check FAILED (IP was empty) for User: '" username "'.", "DEBUG", currentVerbosity) ; Debug IP Missing
                }
            }
            else
            {
                ; If ParseLogLine returned False, check if the line *looked* like a failure event initially:
                ; Counts lines that matched the regex pattern but failed critical parsing steps (timestamp/user/misc).
                if RegExMatch(currentLine, CONFIG["FailedLoginPattern"])
                {
                    failedParseCount++
                }
            }

            ; --- Update Progress Bar Periodically ---
            ; Check if the current line number is a multiple of the update interval to avoid excessive GUI updates.
            if Mod(lineCount, CONFIG["UpdateIntervalLines"]) = 0
            {
                currentPos := fileObject.Pos ; Get the current byte position in the file
                percentage := Floor((currentPos / totalSize) * 100) ; Calculate percentage completion
                try
                {
                    ; Update the GUI progress bar and status text.
                    guiObj.progressBar.Value := percentage
                    guiObj.statusText.Value := "Processing line " lineCount "... (" percentage "%)"
                }
                catch Error as e
                {
                    ; Log errors during GUI updates but don't stop processing.
                    LogMessage("Error updating GUI progress: " e.Message, "WARNING", currentVerbosity)
                }
                ;Sleep(1) ; Tiny sleep to allow GUI thread some time (may not be necessary, sleeps depends on the machine).
            }
        }
        LogMessage("ProcessLogFile: Finished main processing loop (EOF reached). Lines processed: " lineCount, "DEBUG", currentVerbosity) ; Debug Loop End
    }
    catch Error as e
    {
        ; Catch any unexpected errors during the main loop (parsing, map updates, etc.).
        LogMessage("Error reading log file around line " lineCount ". Error: " e.Message ". Log line: " currentLine, "ERROR", currentVerbosity)
        ; Attempt to update the GUI status.
        try {
			guiObj.statusText.Value := "Error reading log file near line " lineCount ": " e.Message
		} catch { ; Ignore errors updating GUI if GUI itself is causing issues.
        ; Note: Processing continues to the finally block after this.
		}
    }
    finally
    {
        ;LogMessage("ProcessLogFile: Entering finally block.", "DEBUG", currentVerbosity) ; Debug Finally Start
        ; Ensure the file object is closed if it was successfully opened.
        if IsObject(fileObject)
        {
            LogMessage("ProcessLogFile: Closing file object.", "DEBUG", currentVerbosity) ; Debug File Close
            fileObject.Close()
        }
        ;LogMessage("ProcessLogFile: Exiting finally block.", "DEBUG", currentVerbosity) ; Debug Finally End
    }

    ; --- 4. Summary Logging ---
    LogMessage("ProcessLogFile: Preparing summary log. Final missingIPCount = " missingIPCount, "DEBUG", currentVerbosity) ; Debug Summary Prep
	
	; Calculate percentages (handle division by zero if lineCount is 0)
    local percFailedParse := (lineCount > 0) ? Format("{:.2f}%", (failedParseCount / lineCount) * 100) : "N/A"
    local percMissingIP := (parsedCount > 0) ? Format("{:.2f}%", (missingIPCount / parsedCount) * 100) : "N/A" ; % of *parsed* events
	
	local summaryBase := "Processed " lineCount " lines. Parsed " parsedCount " failure events."
    local summaryDetails := failedParseCount " lines matched pattern but failed parsing (" percFailedParse "). "
                        . missingIPCount " parsed events were missing IP address (" percMissingIP ")."
	
    if (currentVerbosity < 4) ; Quick Analysis Mode
    {
        LogMessage("Quick Analysis Summary: " summaryBase " - " summaryDetails, "INFO", currentVerbosity)
    }
    else ; Detailed Analysis Mode
    {
        LogMessage("Detailed Analysis: " summaryBase " - " summaryDetails, "INFO", currentVerbosity)
    }
	
    ; --- 5. Final Return ---
    LogMessage("ProcessLogFile: Final check before return. ipDataMap.Count = " ipDataMap.Count, "DEBUG", currentVerbosity) ; Debug Final Check
    LogMessage("ProcessLogFile: Returning TRUE (successfully reached the end).", "DEBUG", currentVerbosity) ; Debug Return True
    return true
}

; ------------------------------------------------------------------------------
; Function: ParseLogLine
; Description: Parses a single log line to extract relevant information like
;              timestamp, IP address, and event type (e.g., FailedLogin).
; Parameters:
;   logLine {string} - Contains a single line from the log file.
;   currentVerbosity {int} - 3 or 4 to log details on execution.log
;
; Returns:
;   A {Map} object with parsed data (e.g., {Type: "FailedLogin", Timestamp: "YYYYMMDD...", IP: "x.x.x.x"})
;   or False if the line is irrelevant or cannot be parsed.
; ------------------------------------------------------------------------------

ParseLogLine(logLine, currentVerbosity) {
    local matchTimestamp, matchIP, matchUsername, ipAddress, timestampYMD, username

    FAILED_LOGIN_PATTERN := CONFIG["FailedLoginPattern"]
	IP_ADDRESS_PATTERN := CONFIG["IPAddressPattern"]
	TIMESTAMP_PATTERN := CONFIG["TimestampPattern"]
	USERNAME_PATTERN := CONFIG["UsernameExtractionPattern"]

    if RegExMatch(logLine, FAILED_LOGIN_PATTERN) {

        ; --- Essential: Extract Timestamp ---
		; Logs into execution.log if timestamp or users are missing.
        if not RegExMatch(logLine, TIMESTAMP_PATTERN, &matchTimestamp) {
            ; Log only in detailed mode
            LogMessage("Failure pattern matched, but couldn't extract timestamp structure: " logLine, "DEBUG", currentVerbosity)
            ;return false
        }
		
        timestampYMD := ConvertLogTimestamp(matchTimestamp) ; ConvertLogTimestamp logs its own warnings
        if (timestampYMD = "") {
            LogMessage("Failure pattern matched, but timestamp is missing: " logLine, "DEBUG", currentVerbosity)
            ;return false
        }

        ; --- Essential: Extract Username ---
        if not RegExMatch(logLine, USERNAME_PATTERN, &matchUsername) {
            ; Log only in detailed mode
            LogMessage("Failure pattern matched, but couldn't extract username: " logLine, "DEBUG", currentVerbosity)
            ;return false
        }
        username := matchUsername[1]

        ; --- Optional: Extract IP Address ---
        ipAddress := ""
        if RegExMatch(logLine, IP_ADDRESS_PATTERN, &matchIP) {
            ipAddress := matchIP[1]
        }
        ; No specific log here if IP is missing, since ProcessLogFile will count it (missingIPCount)

        return Map(
            "Type", "FailedLogin",
            "Timestamp", timestampYMD,
            "Username", username,
            "IP", ipAddress,
            "RawLine", logLine
        )
    }
	; Really noisy, but useful to detect the quality of your log, and how this script parses the info.
	;LogMessage("Line didn't match initial failure pattern: " logLine, "DEBUG", currentVerbosity)
    return false ; Line didn't match initial failure pattern
}

; ------------------------------------------------------------------------------
; Function: AnalyzeBruteForceAttempts
; Description: Analyzes the collected IP data to detect potential brute-force
;              attacks based on the configured threshold and time window.
;
; Parameters:
;   ipDataMap {map} - Contains IP addresses and their failed login timestamps.
;   threshold {int} - The min. number of attempts to trigger a potential alert.
;   timeWindowSeconds {int} - The time window (in seconds) within which the attempts must occur.
;
; Returns:
;   results {map} - Representing a detected potential brute-force incident.
; ------------------------------------------------------------------------------

AnalyzeBruteForceAttempts(ipDataMap, threshold, timeWindowSeconds) {
    local results := []
    local ip, data, timestamps, firstAttemptTS, lastAttemptTS, timeDiffSeconds

    for ip, data in ipDataMap { ; data here is the inner {map}: Map("Attempts": Count, "Timestamps": [...])

        if data["Attempts"] >= threshold { ; Access "Attempts" key
            timestamps := data["Timestamps"] ; Access "Timestamps" key (value is an Array)

            ;timestamps.Sort() ; todo* to Ensure chronological order

            loop timestamps.Length - threshold + 1 {
                local startIndex := A_Index
                local endIndex := A_Index + threshold - 1

                firstAttemptTS := timestamps[startIndex]
                lastAttemptTS := timestamps[endIndex]

                timeDiffSeconds := DateDiff(firstAttemptTS, lastAttemptTS, "Seconds")

                if (timeDiffSeconds >= 0 and timeDiffSeconds <= timeWindowSeconds) {
                    local overallFirstTS := timestamps[1]
                    local overallLastTS := timestamps[timestamps.Length]
                    local overallDuration := DateDiff(overallFirstTS, overallLastTS, "Seconds")
					
					;echo(ip, data["Attempts"], firstAttemptTS, lastAttemptTS, timeDiffSeconds, overallFirstTS, overallLastTS, overallDuration, data["Usernames"])

                    results.Push(Map(
                        "IP", ip,
                        "Attempts", data["Attempts"],
                        "DetectionWindowStart", firstAttemptTS,
                        "DetectionWindowEnd", lastAttemptTS,
                        "WindowDurationSeconds", timeDiffSeconds,
                        "OverallFirstAttempt", overallFirstTS,
                        "OverallLastAttempt", overallLastTS,
                        "OverallDurationSeconds", overallDuration,
						"UsernamesTried", data["Usernames"]
                    ))
                    break ; Found a time window, go to the next IP
                }
            }
        }
    }
    return results
}

; ------------------------------------------------------------------------------
; Function: GenerateReport
; Description: Writes results to the output file AND populates the GUI ListView.
;
; Parameters:
;   outputFilePath {string} - Path + name for the text report file.
;   bruteForceResults {map} - Contains analysis results.
;   usernameFailure {map} - Contains username and count.
;   guiObj {object} - Contains listviews and stuff from gui to be updated.
;   currentVerbosity {int} - Verbosity for execution.log log file.
;
; Returns: True if text report file was written successfully, False otherwise.
; ------------------------------------------------------------------------------

GenerateReport(outputFilePath, bruteForceResults, usernameFailures, guiObj, currentVerbosity) {
    local fileObject, incident, fileWriteSuccess := true
    local startTimeFormatted, endTimeFormatted, firstAttemptFormatted, lastAttemptFormatted
    local username, count

    ; --- Input Validation ---
    if not IsObject(guiObj) or not IsObject(guiObj.bruteForceListView) or not IsObject(guiObj.topUsersListView) {
        LogMessage("GenerateReport called with invalid Gui object or missing ListViews.", "ERROR")
        Return false
    }
    local bfListView := guiObj.bruteForceListView
    local userListView := guiObj.topUsersListView

    ; --- Populate Brute Force ListView ---
    bfListView.Delete() ; Clear previous results
    bfListView.Opt("-Redraw") ; Prevents flicker
    try {
        for incident in bruteForceResults {
            local displayFormat := "yyyy-MM-dd HH:mm:ss"
            startTimeFormatted := FormatTime(incident["DetectionWindowStart"], displayFormat)
            endTimeFormatted := FormatTime(incident["DetectionWindowEnd"], displayFormat)
            firstAttemptFormatted := FormatTime(incident["OverallFirstAttempt"], displayFormat)
            lastAttemptFormatted := FormatTime(incident["OverallLastAttempt"], displayFormat)
			
            ; --- Format Usernames Tried ---
            local usersTriedStr := ""
            local userMap := incident["UsernamesTried"]
            local userList := []
            for user, userCount in userMap {
                 userList.Push({name: user, count: userCount})
            }
            ; Sort users by count descending
            ;userList.Sort( (a, b) => b.count - a.count ) ; *todo .sort - not a priority, just click the listview header instead
			
            ; Build string (e.g., "root(5), admin(2), ...")
            local userCountDisplay := 0
			; Limiting display length, 260 chars in total, windows wrapper fault afaik
            for userItem in userList {
                usersTriedStr .= (usersTriedStr ? ", " : "") userItem.name "(" userItem.count ")"
                userCountDisplay++
                if (userCountDisplay >= 15) {
					usersTriedStr .= ", ... (Further users omited, check report for detailed info.)"
					break 
				}
            }
            if usersTriedStr = "" { 
				usersTriedStr := "(N/A)"
			}
            bfListView.Add(, incident["IP"], incident["Attempts"], usersTriedStr, startTimeFormatted, endTimeFormatted, incident["WindowDurationSeconds"], firstAttemptFormatted, lastAttemptFormatted, incident["OverallDurationSeconds"])
        }
    } catch Error as e {
         LogMessage("Error populating Brute Force ListView: " e.Message, "ERROR")
    } finally {
         bfListView.Opt("+Redraw")
    }
	
	; --- Populate Top Failing Usernames ListView ---
    userListView.Delete() ; Clear previous results
    userListView.Opt("-Redraw") ; Prevents flicker
    try {
         local userFailureList := []
         for username, count in usernameFailures {
              userFailureList.Push({name: username, count: count})
         }
         ; Sort by count descending
         ;userFailureList.Sort( (a, b) => b.count - a.count ) ; *todo .sort - not a priority, just click the listview header instead

         ; Add top N (e.g., top 50) or all to ListView
         local maxUsersToShow := 9999999 ; If data is too noisy or listview lags, reduce.
         loop Min(userFailureList.Length, maxUsersToShow) {
              local userItem := userFailureList[A_Index]
              userListView.Add(, userItem.name, userItem.count)
         }
    } catch Error as e {
         LogMessage("Error populating Top Users ListView: " e.Message, "ERROR")
    } finally {
         userListView.Opt("+Redraw")
    }

    ; --- Write Text Report File ---
    try {
        fileObject := FileOpen(outputFilePath, "w", "UTF-8")
        if not IsObject(fileObject) {
            throw Error("Failed to open output report file for writing: " outputFilePath)
        }
        ; --- Info Header ---
        fileObject.WriteLine("=========================================================")
        fileObject.WriteLine("                  Log Analysis Report          ")
        fileObject.WriteLine("=========================================================")
        fileObject.WriteLine("Generated: " FormatTime(, "yyyy-MM-dd HH:mm:ss"))
        fileObject.WriteLine("Log File Analyzed: " CONFIG["LogFilePath"])
		
	    ; --- Brute Force Section ---
        fileObject.WriteLine("--- Potential Brute Force Incidents (by IP) ---")
        fileObject.WriteLine("Detection Criteria: >= " CONFIG["BruteForceThreshold"] " attempts within " CONFIG["TimeWindowSeconds"] " seconds")
        fileObject.WriteLine("---------------------------------------------------------")
        fileObject.WriteLine("")
		
		if bruteForceResults.Length > 0 {
            for incident in bruteForceResults {
                startTimeFormatted := FormatTime(incident["DetectionWindowStart"], "yyyy-MM-dd HH:mm:ss")
                endTimeFormatted := FormatTime(incident["DetectionWindowEnd"], "yyyy-MM-dd HH:mm:ss")
                firstAttemptFormatted := FormatTime(incident["OverallFirstAttempt"], "yyyy-MM-dd HH:mm:ss")
                lastAttemptFormatted := FormatTime(incident["OverallLastAttempt"], "yyyy-MM-dd HH:mm:ss")

                ; Format usernames tried for text report
                local usersTriedReportStr := ""
                local userMapReport := incident["UsernamesTried"]
                local userListReport := []
                for userR, countR in userMapReport {
					userListReport.Push({name: userR, count: countR})
				}

                for userItemR in userListReport { 
					usersTriedReportStr .= (usersTriedReportStr ? ", " : "") userItemR.name "(" userItemR.count ")"
				}
                if usersTriedReportStr = "" {
					usersTriedReportStr := "(N/A)"
				}

                fileObject.WriteLine("IP Address: " incident["IP"])
                fileObject.WriteLine("  Total Failed Attempts Recorded: " incident["Attempts"])
                fileObject.WriteLine("  Usernames Tried: " usersTriedReportStr)
                fileObject.WriteLine("  (1st) Detected Window:")
                fileObject.WriteLine("    Start Time: " startTimeFormatted)
                fileObject.WriteLine("    End Time:   " endTimeFormatted)
                fileObject.WriteLine("    Duration:   " incident["WindowDurationSeconds"] " seconds (to reach at least " CONFIG["BruteForceThreshold"] " attempts)")
                fileObject.WriteLine("  Overall Activity Period:")
                fileObject.WriteLine("    First Attempt: " firstAttemptFormatted)
                fileObject.WriteLine("    Last Attempt:  " lastAttemptFormatted)
                fileObject.WriteLine("    Total Duration: " incident["OverallDurationSeconds"] " seconds")
                fileObject.WriteLine("---------------------------------------------------------")
            }
        } else {
             fileObject.WriteLine("(No incidents met the configuration criteria)")
             fileObject.WriteLine("---------------------------------------------------------")
        }
        fileObject.WriteLine("")

        ; --- Top Failing Usernames Section ---
        fileObject.WriteLine("--- Top Failing Usernames (Overall) ---")
        fileObject.WriteLine("---------------------------------------------------------")
        if usernameFailures.Count > 0 {
            local userFailureListReport := []
            for usernameR, countR in usernameFailures {
				userFailureListReport.Push({name: usernameR, count: countR})
			}

            fileObject.WriteLine("Username                        | Count")
            fileObject.WriteLine("--------------------------------|--------")
			; Limit users to report, *todo .sort or context will be lost, so big number for now.
            local maxUsersToReport := 9999999 ; Just in case the logs are too big, can reduce this number.
            loop Min(userFailureListReport.Length, maxUsersToReport) {
                local userItem := userFailureListReport[A_Index]
				local formattedLine := Format("{1:-31} | {2}", userItem.name, userItem.count)
				fileObject.WriteLine(formattedLine)
            }
            if userFailureListReport.Length > maxUsersToReport {
                fileObject.WriteLine("... (further entries omitted)")
            }
			fileObject.WriteLine("---------------------------------------------------------")
        } else {
            fileObject.WriteLine("(No failed login attempts recorded)")
            fileObject.WriteLine("---------------------------------------------------------")
        }

    } catch Error as e {
        LogMessage("Error writing report file: " e.Message, "ERROR")
        fileWriteSuccess := false
    } finally {
        if IsObject(fileObject) {
			fileObject.Close() 
		}
    }
    return fileWriteSuccess
}

; ==============================================================================
;                             Utility Functions
; ==============================================================================

; ------------------------------------------------------------------------------
; Function: ConvertLogTimestamp
; Description: Converts timestamp components from regex match object to YYYYMMDDHHMMSS.
;              Assumes current year if year is missing in the log line.
;              So far handles "Mon DD [YYYY] HH:MM:SS" and "YYYY-MM-DD HH:MM:SS" formats.
;
; Parameters:
;   matchTimestamp {object} - The RegExMatch containing captured timestamp parts.
; Returns:
;   {String} The timestamp in YYYYMMDDHHMMSS format, or an empty string on failure.
; ------------------------------------------------------------------------------

ConvertLogTimestamp(matchTimestamp) {
    ; Map month abbreviations to numbers (needed for the older format)
    static monthMap := Map("Jan", "01", "Feb", "02", "Mar", "03", "Apr", "04",
                           "May", "05", "Jun", "06", "Jul", "07", "Aug", "08",
                           "Sep", "09", "Oct", "10", "Nov", "11", "Dec", "12")
    local year, monthNum, day, timePart, formattedDay

    try {
        ; --- Check which timestamp format was matched using array notation ---
		;echo(matchTimestamp)
		
		; *todo add data fills to any date data missing? not a priority, may add wrong context, just year is good enough so far
        if (matchTimestamp[1] != "") {
            ; Format 1 Matched: "Mon DD [YYYY] HH:MM:SS" (Groups 1-4)
            local monthAbbr := matchTimestamp[1] ; Group 1: Month abbreviation (e.g., "Dec")
            day := matchTimestamp[2]             ; Group 2: Day (e.g., "10")
            year := matchTimestamp[3]            ; Group 3: Year (Optional, e.g., "2023" or "")
            timePart := matchTimestamp[4]        ; Group 4: Time (HH:MM:SS)

            ; Handle missing year - Assume current year
            if (year = "") {
                year := A_YYYY ; Use built-in variable for the current year
                ; LogMessage("ConvertLogTimestamp: Assumed current year (" year ") for format 1 timestamp.", "DEBUG")
            }

            ; Validate and get month number from abbreviation
            if not monthMap.Has(monthAbbr) {
                throw Error("Invalid month abbreviation found in format 1 timestamp: '" monthAbbr "'")
            }
            monthNum := monthMap[monthAbbr]

            ; Format day to ensure two digits
            formattedDay := Format("{:02d}", Integer(day))

        } else if (matchTimestamp[5] != "") {
            ; Format 2 Matched: "YYYY-MM-DD HH:MM:SS" (Groups 5-8)
            year := matchTimestamp[5]     ; Group 5: Year (e.g., "2024")
            monthNum := matchTimestamp[6] ; Group 6: Month (e.g., "07")
            day := matchTimestamp[7]      ; Group 7: Day (e.g., "31")
            timePart := matchTimestamp[8] ; Group 8: Time (HH:MM:SS)

            ; Day and Month are already numeric and should be 2 digits from regex,
            ; but formatting day adds consistency if regex was looser.
            formattedDay := Format("{:02d}", Integer(day))
            ; *todo - add validation for monthNum (e.g., ensure it's 01-12)?

        } else {
            ; Neither expected format matched - this indicates an issue upstream or with the regex
            throw Error("Timestamp pattern matched, but neither time format's capture groups were populated.")
        }

        ; --- Common Processing: Format Time and Assemble ---

        timePart := StrReplace(timePart, ":", "")

        ; Basic validation of extracted components
        if (year = "" or monthNum = "" or formattedDay = "" or timePart = "" or StrLen(timePart) != 6) {
             throw Error("Failed to extract or format all timestamp components correctly. Y:" year " M:" monthNum " D:" formattedDay " T:" timePart)
        }
        ; Re-assemble in YYYYMMDDHHMMSS format
        return year . monthNum . formattedDay . timePart

    } catch Error as e {
        ; Log the error and the raw matched string for debugging
        local rawMatch := ""
        try {
             rawMatch := matchTimestamp[0]
        } catch {
            rawMatch := "(Failed to get raw match string)"
        }
        LogMessage("Timestamp conversion error: " e.Message ". Input matched: '" rawMatch "'", "WARN")
        return "" ; Return empty string on failure
    }
}

; ------------------------------------------------------------------------------
; Function: LogMessage
; Description: Writes a message to the script's log file, respecting verbosity level.
;
; Parameters:
;   message {string} - The text message to log.
;   level {string} - The severity level ("INFO", "WARNING", "ERROR", "DEBUG"). Defaults to "INFO".
;   currentVerbosity - The script's current operational verbosity level (e.g., 3 or 4).
; ------------------------------------------------------------------------------

LogMessage(message, level := "INFO", currentVerbosity := 4) { ; Default to detailed if not specified
    local logLine
    static levelMap := Map("INFO", 1, "WARNING", 2, "ERROR", 3, "DEBUG", 4) ; Numerical levels

    local messageLevelNum := levelMap.Has(level) ? levelMap[level] : 1 ; Default to INFO if level unknown

    ; Only log if the message's level is important enough for the current setting
    ; INFO(1), WARNING(2), ERROR(3) always log if currentVerbosity >= 3 (Quick or Detailed)
    ; DEBUG(4) only logs if currentVerbosity >= 4 (Detailed)
    if (messageLevelNum <= currentVerbosity){
        try {
            logLine := FormatTime(, "yyyy-MM-dd HH:mm:ss") " [" level "] " message "`n"
            FileAppend(logLine, CONFIG["ScriptLogPath"], "UTF-8")
        } catch Error as e {
            OutputDebug("CRITICAL: Failed to write to log file " CONFIG["ScriptLogPath"] ". Error: " e.Message)
        }
    }
}

; ------------------------------------------------------------------------------
; Function: DateDiff
; Description: Calculates the difference between two YYYYMMDDHHMMSS timestamps.
;              Uses ConvertToSecondsSinceEpoch as helper func.
;
; Parameters:
;   StartTime {} - The earlier timestamp (YYYYMMDDHHMMSS).
;   EndTime {} - The later timestamp (YYYYMMDDHHMMSS).
;   Units {} - The units for the difference ('Seconds', 'Minutes', 'Hours', 'Days'). Case-insensitive.
; Returns:
;   The difference in the specified units, or an empty string on error.
; ------------------------------------------------------------------------------

DateDiff(StartTime, EndTime, Units := "Seconds")
{
    try {
        local ts1 := ConvertToSecondsSinceEpoch(StartTime)
        local ts2 := ConvertToSecondsSinceEpoch(EndTime)

        if (ts1 = "" or ts2 = "")
            throw Error("Invalid timestamp format for DateDiff")

        diffSeconds := ts2 - ts1

        if diffSeconds < 0
             LogMessage("DateDiff Warning: EndTime (" EndTime ") is earlier than StartTime (" StartTime "). Result will be negative: " diffSeconds , "WARNING")

        Switch StrLower(Units)
        {
            Case "seconds": return diffSeconds
            Case "minutes": return Floor(diffSeconds / 60)
            Case "hours":   return Floor(diffSeconds / 3600)
            Case "days":    return Floor(diffSeconds / 86400)
            Default:        throw Error("Invalid Units specified for DateDiff: " Units)
        }
    } catch Error as e {
        LogMessage("DateDiff Error: " e.Message " (StartTime: " StartTime ", EndTime: " EndTime ")", "ERROR")
        return ""
    }
}

; Helper for DateDiff - Converts YYYYMMDDHHMMSS to seconds since epoch (approx.)
ConvertToSecondsSinceEpoch(TimestampYMD) {
    if not RegExMatch(TimestampYMD, "^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", &m)
        return ""

    try {
         local year := Integer(m[1]), month := Integer(m[2]), day := Integer(m[3])
         local hour := Integer(m[4]), min := Integer(m[5]), sec := Integer(m[6])

         local days := (year - 1) * 365 + Floor((year - 1) / 4) - Floor((year - 1) / 100) + Floor((year - 1) / 400)
         local daysInMonth := [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
         loop month - 1 {
             days += daysInMonth[A_Index]
         }
         if (month > 2 and (Mod(year, 4) = 0 and Mod(year, 100) != 0 or Mod(year, 400) = 0)) {
             days += 1
         }
         days += day -1

         local totalSeconds := days * 86400 + hour * 3600 + min * 60 + sec
         return totalSeconds
    } catch {
        return ""
    }
}

;Reload hotkey ctrl+r, for testing purposes.
/*

^r::{
Reload
}

*/
