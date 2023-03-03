# Hideme_Rootkit

### What does the Rootkit do?
interface between the user space to kernel space where the rootkit resides.
Keylogging.
* Hiding the rootkit from lsmod command.
* Turning a simple user into a root.
* Hiding files in the system.
* Hiding processes in the system.

### How It Works-
interface between the user space to kernel space:
The rootkit I wrote is a kernel module, that is, a piece of code that is loaded into the kernel at runtime. Most of the uses of kernel module are for device drivers and indeed the rootkit I wrote is also a device driver. It is linked to a device called /dev/hideme and actually implements functions to read and write to it.
The driver will ignore any writing to the device except for the following magic numbers:
* givekeys, hidekeys
* showmodule, hidemodule 
* giveroot, leaveroot
* showfiles, hidefiles 
* showproc, hideproc
In addition, therootkit makes a hook to the kill command (will be explained later) and through the command you can also interface with it.

### Keylogging
From the moment that the rootkit enters the kernel it starts recording keystrokes. It does this through a notifier chain, and uses it for malicious purposes. Thus, every time a button is pressed on the keyboard, when in the chain it reaches the rootkit, it will record it in a buffer of size 1024 bytes.
In order to receive the keystrokes of the keyboard, you must write to device named /dev/hide the string: "givekeys". And then you can read from the device and receive the keyboard keystrokes. To hide the keyboard keys again, write the string: "hidekeys".

### lsmod hiding-
To keep track of the modules loaded into kernel memory, the kernel uses the data structure- A linked list. Since we have access to the same data structure, we can remove our module from the structure and thus when we run the command lsmod the kernel goes through the chain and it will not find our module. It is also necessary to save the position of the previous link, because when we want to delete the module from the memory, we will need the module to appear in the chain. In order to hide the module, write the string: "hidemodule" to the device. And to add the module back to the chain, write the string: "showmodule" to the device.

### Turning a simple user into aroot-
In linux every task can change its credentials. Therefore, you can simply access the cred struct, change the uid, guid... to 0 (root) and thus we can give a process of a simple user root privileges. We will store the values ​​in cred, so we can restore the user's old permissions. To get root privileges, write the string: "giveroot" to the device and to return to user simply write the string: "leaveroot" to the device.

### Hiding files in the system-
To search for files in the system, ls uses a syscall called getdents. In order to change the content returned from the command, it is necessary to make a hook to the system command. In the latest kernel versions, it is not possible to get the pointer to the syscall table, so it will be necessary to find it in memory and send it as a parameter to the rootkit. After we do this we will change the pointer to the getdents function. The new function will call the original getdents and save the return value. After that, it will pass on dirent which is the struct in which the getdents command is used. This struct has the name of the file and the size of the struct so that we can go through all the structs (since there are several in each folder) and check if the file name starts with a magic number called hideme. If so, we'll make the original getdents skip the struct. We do this by adding the size of the struct to the previous struct. So when getdents goes through the structs, it will skip the struct that contains the file you want to hide, this is because the previous struct has a variable that also contains the size of the next struct.
To hide the files, write to the device the string:”hidefiles”. To show the files, write the string: "showfiles".

### Hiding processes in the system-
In order to check which processes are running in the system, ps also uses getdents, so we will follow the same principle. The difference is that we want to hide one process at a time. What we will hide this time is the pid. In order to get the pid we need to get the input from the user. But instead of getting involved with writing to the device and removing the process from it, you can make a hook to the kill function. Why this function? The function accepts the process as a parameter. Since signal 64 is not used, if we send this signal to the kill function after hooking it, it will take care of hiding the process. Again, in order to hide the process, we will make a hook to getdents as I explained earlier.
In order to activate the hooking write the string: "hideproc" to the device. In order to restore the original functions, write the string: "showproc" to the device.
In order to hide a process, after running the hooking the signal 64 must be sent to the process you want to hide.

### Manual-
in order to use the rootkit you need three files: hideme_rootkit.ko, hideme_start, Makefile. In order to insert the module into memory you need root privileges and use the make command (it is important to note that the headers of the linux kernel must be compatible, therefore it is necessary to download them, for example using apt-get install linux-headers, if there are problems you can check if lib/modules exists A folder called the kernel version and there should be a symbolic link to /usr/src)
After that, the script must be given run permissions hideme_start which is responsible both for finding the location of the sys call table and for putting the module into memory. Finally, run the script. If you want to remove the module from memory, use the command: rmmod hideme_rootkit.ko.
Then you can use the commands as I explained earlier.	

- Tested on kernel version5.10.0 on the Kali distribution.
