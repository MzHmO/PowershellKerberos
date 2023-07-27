# PowershellKerberos
Some scripts to abuse kerberos using Powershell. Check how to use video (Thanks to [@BRIPWN](https://twitter.com/BriPwn))
- [YouTube](https://youtu.be/UvQPRFo_w54)

## Injector.ps1
Small tool for injecting kerberos tickets. Supports two work modes:
- U can read ticket from kirbi file (1 mode)
- U can read ticket from b64 (2 mode)

Examples:
```powershell
.\injector.ps1 1 A:\SSD\Share\ticket.kirbi

.\injector.ps1 2 "doi.....q"
```
![изображение](https://user-images.githubusercontent.com/92790655/233820720-87d96963-d416-477e-a7ce-68988bc6295d.png)

## Dumper.ps1
This tool allows you to dump Kerberos tickets from the LSA cache. Implemented via Add-Type.

If the tool is run as a privileged user, it will automatically obtain NT AUTHORITY\SYSTEM privileges and then dump all tickets. If the tool is run as a non-privileged user, it will only dump tickets from the current logon session.

Examples:
```powershell
.\dumper.ps1
```
![изображение](https://github.com/MzHmO/PowershellKerberos/assets/92790655/d140e573-f220-424a-bf2d-857a65df044f)
![изображение](https://github.com/MzHmO/PowershellKerberos/assets/92790655/93c7c694-0920-4811-955f-9b9e2617a10a)
![изображение](https://github.com/MzHmO/PowershellKerberos/assets/92790655/0c1cf1fa-2262-44b9-a7a4-05fc820df5ef)
