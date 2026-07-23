**Recon Engine: Your Discovery Awaits!**  
   
 A cli reconnaissance tool that probes HTTP and line‑protocol services on loopback addresses, all within a strict scope and request budget.  
**Features**  
- **Scope‑aware**: Only probes ports explicitly marked in scope.  
- **Rate limiting**: Configurable requests per second (default: 25).  
- **Request budget**: Stops after 240 requests to avoid overloading the target.  
- **Automatic wildcard detection**: Avoids false positives on wildcard HTTP endpoints.  
- **Checkpoint / resumption**: Saves progress, you can resume after interrupt  
**Requirements**  
- Python 3.11+  
- macOS, Linux, or Ubuntu VM  
**Installation**  
1. Clone or download the repository.  
2. Ensure the directory structure is as seen  
**Usage**  
1. Test from the **/recon-engine** directory using any of the commands below:  
   
    
   
  pytest tests -v  
   
    
   
  python3 -m unittest discover -s tests -v  
2. Start the lab from the **/ubi-stage5-eh** directory using the command below:  
   
    
   
  python3 lab/evidence/local_lab.py --marker UBI-A5-811A227F3A50 --output lab-runtime  
3. Run the engine from the **/recon-engine** directory using the command below:  
   
    
   
  python3 -m engine.cli --target 127.0.0.1 --scope /home/sstarr/Documents/ubi-stage5-eh/lab-runtime/scope.csv --output run --rate 25  
**Steps**  
1. Start the lab from the **/ubi-stage5-eh** directory using the command below:  
   
    
   
  python3 lab/evidence/local_lab.py --marker UBI-A5-811A227F3A50 --output lab-runtime  
2. Run the engine from the **/recon-engine** directory using the command below:  
   
    
   
  python3 -m engine.cli --target 127.0.0.1 --scope /home/sstarr/Documents/ubi-stage5-eh/lab-runtime/scope.csv --output run --rate 25  
**Troubleshooting**  
- **Error:** ModuleNotFoundError: No module named 'engine'  
- **Solution:** Run from the project root or set PYTHONPATH.  
