// CheckAlyac.cpp : Defines the entry point for the console application.
#include "stdafx.h"
#include <iostream>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string>
#include <atlstr.h>
#include <ctime>
using namespace std;

int main()
{	
	enum ConsoleColors
	{
		BlackFore   = 0,
		MaroonFore  = FOREGROUND_RED,
		GreenFore   = FOREGROUND_GREEN,
		NavyFore    = FOREGROUND_BLUE,
		TealFore    = FOREGROUND_GREEN | FOREGROUND_BLUE,
		OliveFore   = FOREGROUND_RED | FOREGROUND_GREEN,
		PurpleFore  = FOREGROUND_RED | FOREGROUND_BLUE,
		GrayFore    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
		SilverFore  = FOREGROUND_INTENSITY,
		RedFore     = FOREGROUND_INTENSITY | FOREGROUND_RED,
		LimeFore    = FOREGROUND_INTENSITY | FOREGROUND_GREEN,
		BlueFore    = FOREGROUND_INTENSITY | FOREGROUND_BLUE,
		AquaFore    = FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE,
		YellowFore  = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN,
		FuchsiaFore = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE,
		WhiteFore   = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,

		BlackBack   = 0,
		MaroonBack  = BACKGROUND_RED,
		GreenBack   = BACKGROUND_GREEN,
		NavyBack    = BACKGROUND_BLUE,
		TealBack    = BACKGROUND_GREEN | BACKGROUND_BLUE,
		OliveBack   = BACKGROUND_RED | BACKGROUND_GREEN,
		PurpleBack  = BACKGROUND_RED | BACKGROUND_BLUE,
		GrayBack    = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE,
		SilverBack  = BACKGROUND_INTENSITY,
		RedBack     = BACKGROUND_INTENSITY | BACKGROUND_RED,
		LimeBack    = BACKGROUND_INTENSITY | BACKGROUND_GREEN,
		BlueBack    = BACKGROUND_INTENSITY | BACKGROUND_BLUE,
		AquaBack    = BACKGROUND_INTENSITY | BACKGROUND_GREEN | BACKGROUND_BLUE,
		YellowBack  = BACKGROUND_INTENSITY | BACKGROUND_RED | BACKGROUND_GREEN,
		FuchsiaBack = BACKGROUND_INTENSITY | BACKGROUND_RED | BACKGROUND_BLUE,
		WhiteBack   = BACKGROUND_INTENSITY | BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE,
	};

	const HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTitle("Check Alyac");

	// Resize console
	HWND console = GetConsoleWindow();
	RECT ConsoleRect;
	GetWindowRect(console, &ConsoleRect); 
    MoveWindow(console, ConsoleRect.left, ConsoleRect.top, 650, 750, TRUE);

	// Disable maximize button
	DWORD style = GetWindowLong(console, GWL_STYLE);
	style &= ~WS_MAXIMIZEBOX;
	SetWindowLong(console, GWL_STYLE, style);
	SetWindowPos(console, NULL, 0, 0, 0, 0, SWP_NOSIZE|SWP_NOMOVE|SWP_FRAMECHANGED);

	char *computer_name[] = {
		"COM01","COM02","COM03","COM04","COM05",
		"COM06","COM07","COM08","COM09","COM10",
		"COM11","COM12","COM13","COM14","COM15",
		"COM16", "COM17","COM18","COM19","COM20",
		"COM21","COM22","COM23","COM24","COM25",
		"COM26", "COM27","COM28","COM29","COM30"
	};

	CString ip_head("192.168.1.");
	char *ip_tail[] = {
		"21","21","21","21","21",
		"21","21","21","21","21",
		"21","21","21","21","21",
		"21","21","21","21","21",
		"21","21","21","21","21",
		"26","27","28","29","30"
	}; // 192.168.1.21 is an IP address for dummy data

	// Update path
	CString tail_update_path("\\C$\\ProgramData\\ESTsoft\\ALYac\\update\\");
	CString base_win("");

	// Scan Path
	CString tail_scan_path("\\C$\\ProgramData\\ESTsoft\\ALYac\\log\\server_scan");

	// Get current time
	time_t ttime = time(0);
	tm *local_time = localtime(&ttime);
	int currentDay, currentMonth, currentYear = 0;
	currentDay = local_time->tm_mday;
	currentMonth = 1 + local_time->tm_mon;
	currentYear = 1900 + local_time->tm_year;

    int index = 0;
	while(index < 30)
	{
		CString ip_address(ip_head + ip_tail[index]);
		CString com_name(computer_name[index]);
		CString last_update("");
		CString last_scan("");

		// Check the update data path based on the bit version of Windows.
		if(com_name == "COM06" || com_name == "COM07" || com_name == "COM08" || com_name == "COM09" || com_name == "COM10")
		{
			base_win = "alyac\\x64\\config.dat";
		}
		else if(com_name == "COM16" || com_name == "COM17" || com_name == "COM18" || com_name == "COM19" || com_name == "COM20")
		{
			base_win = "config.dat";
		}
		else
		{
			base_win = "alyac\\x86\\config.dat";
		}

		CString update_path("\\\\" + ip_head + ip_tail[index] + tail_update_path + base_win);
		CString scan_path("\\\\" + ip_head + ip_tail[index] + tail_scan_path);

		char timeStr[100] = "";
		struct stat buf;
		time_t ltime;
		char datebuf [9];
		char timebuf [9];

		string dateTimeStr, monthUpdateStr, yearUpdateStr, monthScanStr, yearScanStr;
		int monthUpdateInt, yearUpdateInt, monthScanInt, yearScanInt = 0;

		// Get the last update of the Alyac antivirus
		if (!stat(update_path, &buf))
		{
			strftime(timeStr, 100, "%H:%M:%S %Y-%m-%d", localtime( &buf.st_mtime));
			last_update = timeStr;
			dateTimeStr = last_update;
			yearUpdateStr  = dateTimeStr.substr(9,4);
			monthUpdateStr = dateTimeStr.substr(14,2);
			yearUpdateInt  = stoi(yearUpdateStr);
			monthUpdateInt = stoi(monthUpdateStr);
		}
		else
		{
			last_update = "Unable to access " + com_name;
		}

		// Get the last scan of the Alyac antivirus
		if (!stat(scan_path, &buf))
		{
			strftime(timeStr, 100, "%H:%M:%S %Y-%m-%d", localtime( &buf.st_mtime));
			last_scan = timeStr;
			dateTimeStr = last_scan;
			yearScanStr = dateTimeStr.substr(9,4);
			monthScanStr = dateTimeStr.substr(14,2);
			yearScanInt = stoi(yearScanStr);
			monthScanInt = stoi(monthScanStr);
		}
		else
		{
			last_scan = "Unable to access " + com_name;
		}

		// Display the result
		SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::WhiteFore);
		switch(index)
		{
			case 0:
				printf("                         ===  LATEST  UPDATE  === | ===   LATEST SCAN   ===\n");
				printf(" Section 1 :                                      |\n");
				break;
			case 5:
				printf("\n Section 2 :\n");
				break;
			case 10:
				printf("\n Section 3 :\n");
				break;
			case 15:
				printf("\n Section 4 :\n");
				break;
			case 20:
				printf("\n Section 5 :\n");
				break;
			case 25:
				printf("\n Section 6 :\n");
				break;
		}

		// Unable to access the PC (displayed in red if true)
		if(last_update.Mid(0,16) == "Unable to access" || last_scan.Mid(0,16) == "Unable to access")
		{
			SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::RedFore);
		}
		// Compare the datetime result with the current time (displayed in yellow if true)
		else if((currentYear == yearUpdateInt || currentYear == yearScanInt))
		{
			if(currentDay > 5)
			{
				if(monthUpdateInt != currentMonth || monthScanInt != currentMonth)
				{
					SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::YellowFore);
				}
			}

			if((abs(monthUpdateInt-currentMonth) > 1 && currentYear == yearUpdateInt) || (abs(monthScanInt-currentMonth) > 1 &&currentYear == yearScanInt))
			{
				SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::YellowFore);
			}
		}
		else if((currentYear > yearUpdateInt || currentYear > yearScanInt))
		{
			if(currentDay > 5)
			{
				SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::YellowFore);
			}
			else if (currentYear > yearUpdateInt && (monthUpdateInt < 12 || monthScanInt < 12))
			{
				SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::YellowFore);
			}
		}

		printf("  %.5s - %-13s : %22.22s  |  %22.22s \n", com_name, ip_address, last_update, last_scan);
		index++;
	}

	SetConsoleTextAttribute(hConsole, ConsoleColors::BlackBack | ConsoleColors::WhiteFore);
	printf("\n");
	system("pause");
}

