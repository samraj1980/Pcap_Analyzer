from django.shortcuts import render
#from django.conf import settings
from django.core.files.storage import FileSystemStorage
import os
from pcap_analyzer import analyzepcap
from django.utils.encoding import smart_str
from django.http import HttpResponse

#from Pcap_Analyzer.pcapanalyzer.forms import Protocol form


def index(request):
    progress = 0
# Check if the HTML form is a post mode and increment the progress bar to 5%    

    if(request.POST.get('Analyzebtn')):
        progress = 5
         
# Check if there is a file selected in the request files widget and if yes check the extension of the file. 
# if the extension is not PCAPNG, then raise an error message 
    
        if len(request.FILES) != 0: 
            myfile = request.FILES['myfile']
            fs = FileSystemStorage()            
            extension = os.path.splitext(myfile.name)[1]
            valid_extensions = ['.pcap', '.pcapng', '.cap']
            if not extension.lower() in valid_extensions:                
                message1 = "-danger"
                message2 = "Error !! File selected is a" + extension +  " file. Please select a valid Pcap file to load."            
                return render(request, 'pcapanalyzer/home.html',  {"message1": message1 , "message2" : message2} )       

# Then load the file into the server under the media folder. 
            
            myfile.name = myfile.name.replace(" ", "_")
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            print uploaded_file_url
            progress = 50       
            
#            return render(request, 'pcapanalyzer/home.html', { "progress": progress, 'uploaded_file_url': uploaded_file_url})

# Now execute the Python program which actually analyzes the uploaded PCAP file. 
            
            out_file = analyzepcap(uploaded_file_url) 
            
#            out_file_url = fs.url(out_file)
            out_file_url =  out_file                
            #print out_file_url 
            
            
            progress = 100       
#            response = HttpResponse(content_type='application/vnd.ms-excel')
#            response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(out_file)
#            response['X-Sendfile'] = smart_str(out_file_url)
#            print smart_str(out_file_url)
#            return response 
            return render(request, 'pcapanalyzer/home.html', { "progress": progress, 'uploaded_file_url': uploaded_file_url, "out_file_url": out_file_url})
#            return render(request, 'pcapanalyzer/home.html', { "progress": progress, 'uploaded_file': filename, "out_file": out_file})
            
            


# If there is no file selected then raise an error message. 
        
        else:
            message1 = "-danger"
            message2 = "Error !! Please select a Pcap file to load."            
            return render(request, 'pcapanalyzer/home.html',  {"message1": message1 , "message2" : message2} )
    
# If the cancel button is raised then reset the form and error message box

    if(request.POST.get('cancelbtn')):
        progress = 0
        return render(request, 'pcapanalyzer/home.html', { "progress": progress})
    

# return the processed form back 

    return render(request, 'pcapanalyzer/home.html')



