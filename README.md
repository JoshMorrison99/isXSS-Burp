# isXSS-Burp
Burp extension used to find reflected html characters in parameters. This plugin works by sending an altered request in the background with the parameter values replaced with the value `xxxx1'xxxx2"xxxx3>xxxx4<`. The plugin will then search for the values in the response to check which html characters are being encoded.

![image](https://user-images.githubusercontent.com/25315255/229309547-a7fa8fc3-9d11-4948-9e65-e888a6a20ea6.png)
