butane --pretty --strict coreos.bu --output coreos.ign
.\kvpctl.exe coreos clear
.\kvpctl.exe coreos add-ign .\coreos.ign
