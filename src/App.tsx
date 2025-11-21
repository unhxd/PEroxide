import { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useQuery } from '@tanstack/react-query';
import { Button } from './components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { Progress } from './components/ui/progress';
import { Badge } from './components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './components/ui/table';
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { FixedSizeList as List } from 'react-window';
import { Upload, FileText, AlertTriangle, Shield } from 'lucide-react';
import useScanStore from './store';

// Use window.location.hostname to automatically use the same host as the frontend
const API_BASE = `http://${window.location.hostname}:3001/api`;

interface ScanResult {
  status: 'safe' | 'unsafe' | 'scanning';
  threats: { type: string; details: string }[];
  stats: { threatsFound: number };
  logs: string[]; // Array of log lines
  file_info?: {
    filename: string;
    size: number;
    sha256: string;
  };
}

const App: React.FC = () => {
  const { scanId, setScanId, progress, setProgress, message, setMessage } = useScanStore();
  const [uploadProgress, setUploadProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [uploadedFile, setUploadedFile] = useState<{ name: string; size: number } | null>(null);

  const onDrop = (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    // Clear any previous error
    setErrorMessage(null);
    setUploadedFile({ name: file.name, size: file.size });
    setIsUploading(true);
    
    // Create FormData for file upload
    const formData = new FormData();
    formData.append('file', file);

    // Use XMLHttpRequest for upload progress tracking
    const xhr = new XMLHttpRequest();

    // Track upload progress
    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) {
        const percentComplete = (e.loaded / e.total) * 100;
        setUploadProgress(Math.min(percentComplete, 99)); // Cap at 99% until response
      }
    });

    // Handle completion
    xhr.addEventListener('load', () => {
      setUploadProgress(100);
      setIsUploading(false);

      if (xhr.status === 200) {
        try {
          const data = JSON.parse(xhr.responseText);
          
          // Check if the response contains an error
          if (data.error) {
            setErrorMessage(data.error);
            return;
          }
          
          setScanId(data.scanId);
          startSSE(data.scanId);
        } catch (err) {
          console.error('Failed to parse response:', err);
          setErrorMessage('Invalid response from server');
        }
      } else {
        try {
          const data = JSON.parse(xhr.responseText);
          setErrorMessage(data.error || `Upload failed with status ${xhr.status}`);
        } catch {
          setErrorMessage(`Upload failed with status ${xhr.status}`);
        }
      }
    });

    // Handle errors
    xhr.addEventListener('error', () => {
      setIsUploading(false);
      setErrorMessage('Upload failed. Please make sure the backend server is running.');
    });

    // Send the request
    xhr.open('POST', `${API_BASE}/upload`);
    xhr.send(formData);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop, 
    maxFiles: 1,
    multiple: false
  });

  const startSSE = (id: string) => {
    const eventSource = new EventSource(`${API_BASE}/scan-status/${id}`);
    
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setProgress(data.progress);
        setMessage(data.message);
        setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${data.message}`]);
        
        if (data.progress >= 100) {
          eventSource.close();
        }
      } catch (error) {
        console.error('Error parsing SSE data:', error);
      }
    };

    eventSource.onerror = (error) => {
      console.error('SSE Error:', error);
      eventSource.close();
    };
  };

  const { data: result } = useQuery<ScanResult>({
    queryKey: ['scanResult', scanId],
    queryFn: async () => {
      if (!scanId) throw new Error('No scan ID');
      const res = await fetch(`${API_BASE}/scan-result/${scanId}`);
      if (!res.ok) throw new Error('Failed to fetch scan result');
      const data = await res.json();
      console.log('Scan result received:', data);
      return data;
    },
    enabled: !!scanId && progress === 100,
    retry: 3,
  });

  const chartData = result 
    ? [
        { name: 'Threats', value: result.stats.threatsFound },
        { name: 'Safe', value: Math.max(0, 100 - result.stats.threatsFound) }
      ]
    : [];
  
  const COLORS = ['#FF8042', '#00C49F'];

  const LogRow = ({ index, style }: { index: number; style: React.CSSProperties }) => (
    <div style={style} className="px-2">
      <div className="text-xs font-mono text-rust-300 bg-black px-2 py-1 hover:bg-zinc-900/50 transition-colors">
        <span className="text-rust-600 mr-2">›</span>
        {logs[index]}
      </div>
    </div>
  );

  const resetScanner = () => {
    setScanId(null);
    setProgress(0);
    setMessage('');
    setLogs([]);
    setUploadProgress(0);
    setErrorMessage(null);
    setUploadedFile(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-zinc-900 to-black p-8">
      <Card className="max-w-5xl mx-auto shadow-2xl bg-zinc-900 border-rust-700/50">
        <CardHeader className="bg-gradient-to-r from-rust-800 to-rust-900 text-white rounded-t-lg border-b-2 border-rust-600">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-rust-400" />
            <CardTitle className="text-3xl font-bold tracking-tight">PEroxide File Scanner</CardTitle>
          </div>
          <p className="text-rust-200 mt-2 font-mono text-sm">Advanced malware detection and analysis</p>
        </CardHeader>
        <CardContent className="pt-6 bg-zinc-900">
          {!scanId ? (
            <div>
              <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-lg p-12 text-center transition-all cursor-pointer ${
                  isDragActive 
                    ? 'border-rust-500 bg-rust-950/30 scale-105 shadow-lg shadow-rust-900/50' 
                    : 'border-rust-800/50 hover:border-rust-600 hover:bg-zinc-800/50 bg-black/40'
                }`}
              >
                <input {...getInputProps()} />
                <Upload className="mx-auto h-16 w-16 text-rust-500 mb-4" />
                {isDragActive ? (
                  <p className="text-lg font-semibold text-rust-400">Drop the file here...</p>
                ) : (
                  <>
                    <p className="text-lg font-semibold text-gray-200 mb-2">
                      Drag & drop a file here, or click to select
                    </p>
                    <p className="text-sm text-gray-500 font-mono">
                      PE file & shellcode analysis • Max size: 100MB
                    </p>
                  </>
                )}
              </div>
              {errorMessage && (
                <div className="mt-6 bg-red-950/50 p-4 rounded-lg border-2 border-red-800">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-6 w-6 text-red-400 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-red-400 mb-1 font-mono">Upload Rejected</h3>
                      <p className="text-red-300 font-mono text-sm mb-2">{errorMessage}</p>
                      {uploadedFile && (
                        <div className="text-xs text-red-400/80 font-mono mt-2 bg-red-950/30 p-2 rounded">
                          <p>File: {uploadedFile.name}</p>
                          <p>Size: {(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB</p>
                        </div>
                      )}
                      <Button 
                        onClick={() => {
                          setErrorMessage(null);
                          setUploadedFile(null);
                        }} 
                        className="mt-3 bg-red-800 hover:bg-red-700 text-white font-mono text-sm"
                      >
                        Try Another File
                      </Button>
                    </div>
                  </div>
                </div>
              )}
              {isUploading && !errorMessage && (
                <div className="mt-6 bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-medium text-rust-400 font-mono">Uploading...</span>
                    <span className="text-sm font-medium text-rust-400 font-mono">{Math.round(uploadProgress)}%</span>
                  </div>
                  <Progress value={uploadProgress} className="h-3" />
                  {uploadedFile && (
                    <div className="text-xs text-rust-400/80 font-mono mt-2">
                      <p>File: {uploadedFile.name}</p>
                      <p>Size: {(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : progress < 100 ? (
            <div className="space-y-6">
              {uploadedFile && (
                <div className="bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                  <h4 className="text-sm font-semibold text-rust-400 mb-2 font-mono">File Information</h4>
                  <div className="text-sm text-gray-300 font-mono space-y-1">
                    <p><span className="text-rust-500">Name:</span> {uploadedFile.name}</p>
                    <p><span className="text-rust-500">Size:</span> {(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB ({uploadedFile.size.toLocaleString()} bytes)</p>
                  </div>
                </div>
              )}
              <div className="bg-zinc-800/50 p-6 rounded-lg border border-rust-800/30">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xl font-semibold text-rust-400 font-mono">Scanning in Progress</h3>
                  <Badge variant="secondary" className="text-sm px-3 py-1 bg-rust-900 text-rust-300 border-rust-700 font-mono">
                    {Math.round(progress)}%
                  </Badge>
                </div>
                <Progress value={progress} className="h-4 mb-3" />
                <p className="text-gray-300 font-medium font-mono text-sm">{message}</p>
              </div>
              
              <div>
                <h4 className="text-sm font-semibold text-rust-400 mb-2 flex items-center gap-2 font-mono">
                  <FileText className="h-4 w-4" />
                  Scan Logs
                </h4>
                <div className="bg-black rounded-lg overflow-hidden border-2 border-rust-900/50 shadow-inner">
                  {logs.length > 0 ? (
                    <List 
                      height={240} 
                      itemCount={logs.length} 
                      itemSize={32} 
                      width="100%"
                    >
                      {LogRow}
                    </List>
                  ) : (
                    <div className="p-4 text-rust-600 text-sm font-mono">Waiting for scan to start...</div>
                  )}
                </div>
              </div>
            </div>
          ) : result ? (
            result.status === 'scanning' ? (
              // Show loading state while scanning
              <div className="space-y-6">
                {(result.file_info || uploadedFile) && (
                  <div className="bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                    <h4 className="text-sm font-semibold text-rust-400 mb-2 font-mono">File Information</h4>
                    <div className="text-sm text-gray-300 font-mono space-y-1">
                      <p><span className="text-rust-500">Name:</span> {result.file_info?.filename || uploadedFile?.name}</p>
                      <p><span className="text-rust-500">Size:</span> {((result.file_info?.size || uploadedFile?.size || 0) / (1024 * 1024)).toFixed(2)} MB ({(result.file_info?.size || uploadedFile?.size || 0).toLocaleString()} bytes)</p>
                    </div>
                  </div>
                )}
                <div className="bg-zinc-800/50 p-6 rounded-lg border border-rust-800/30">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xl font-semibold text-rust-400 font-mono flex items-center gap-2">
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-rust-400"></div>
                      Analyzing File...
                    </h3>
                    <Badge variant="secondary" className="text-sm px-3 py-1 bg-rust-900 text-rust-300 border-rust-700 font-mono animate-pulse">
                      SCANNING
                    </Badge>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 text-sm text-gray-400 font-mono">
                      <div className="w-2 h-2 bg-rust-500 rounded-full animate-pulse"></div>
                      <span>Deep analysis in progress...</span>
                    </div>
                    <div className="flex items-center gap-3 text-sm text-gray-400 font-mono">
                      <div className="w-2 h-2 bg-rust-500 rounded-full animate-pulse" style={{animationDelay: '0.2s'}}></div>
                      <span>Checking threat signatures...</span>
                    </div>
                    <div className="flex items-center gap-3 text-sm text-gray-400 font-mono">
                      <div className="w-2 h-2 bg-rust-500 rounded-full animate-pulse" style={{animationDelay: '0.4s'}}></div>
                      <span>Finalizing results...</span>
                    </div>
                  </div>
                  <div className="mt-4 bg-black/40 rounded p-3 border border-rust-900/50">
                    <div className="flex items-center justify-between text-xs text-rust-500 font-mono mb-2">
                      <span>Analysis Progress</span>
                      <span className="animate-pulse">Processing...</span>
                    </div>
                    <div className="w-full bg-zinc-900 rounded-full h-2 overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-rust-600 to-rust-400 rounded-full animate-progress-fill"
                      ></div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              // Show final results
              <div className="space-y-6">
                {(result.file_info || uploadedFile) && (
                  <div className="bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                    <h4 className="text-sm font-semibold text-rust-400 mb-2 font-mono">Scanned File</h4>
                    <div className="text-sm text-gray-300 font-mono space-y-1">
                      <p><span className="text-rust-500">Name:</span> {result.file_info?.filename || uploadedFile?.name}</p>
                      <p><span className="text-rust-500">Size:</span> {((result.file_info?.size || uploadedFile?.size || 0) / (1024 * 1024)).toFixed(2)} MB ({(result.file_info?.size || uploadedFile?.size || 0).toLocaleString()} bytes)</p>
                      {result.file_info?.sha256 && (
                        <p><span className="text-rust-500">SHA256:</span> <span className="text-xs break-all">{result.file_info.sha256}</span></p>
                      )}
                      <p><span className="text-rust-500">Status:</span> <span className={result.status === 'safe' ? 'text-emerald-400' : 'text-red-400'}>
                        {result.status === 'safe' ? 'Clean - No threats detected' : 
                         result.status === 'unsafe' ? 'Threats detected' : 
                         result.status}
                      </span></p>
                    </div>
                  </div>
                )}
                <div className="flex items-center justify-between bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                  <h3 className="text-2xl font-bold text-rust-400 font-mono">Scan Complete</h3>
                  <Badge 
                    variant={result.status === 'safe' ? 'default' : 'destructive'}
                    className={`text-lg px-4 py-2 font-mono ${
                      result.status === 'safe' 
                        ? 'bg-emerald-900 text-emerald-300 border-emerald-700' 
                        : 'bg-red-900 text-red-300 border-red-700'
                    }`}
                  >
                    {result.status === 'safe' ? '✓ SAFE' : 
                     result.status === 'unsafe' ? '⚠ THREATS DETECTED' :
                     `STATUS: ${result.status.toUpperCase()}`}
                  </Badge>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                  <CardHeader className="border-b border-rust-900/30">
                    <CardTitle className="text-lg text-rust-400 font-mono">Threat Statistics</CardTitle>
                  </CardHeader>
                  <CardContent className="flex justify-center bg-black/20">
                    {chartData.length > 0 && chartData[0].value > 0 ? (
                      <PieChart width={280} height={280}>
                        <Pie 
                          data={chartData} 
                          dataKey="value" 
                          nameKey="name" 
                          cx="50%" 
                          cy="50%" 
                          outerRadius={100} 
                          fill="#8884d8" 
                          label
                        >
                          {chartData.map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#18181b', border: '1px solid #78350f', color: '#fbbf24' }} />
                        <Legend wrapperStyle={{ color: '#d1d5db' }} />
                      </PieChart>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-64 text-emerald-500">
                        <Shield className="h-24 w-24 mb-4" />
                        <p className="text-xl font-semibold font-mono">No Threats Detected</p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                  <CardHeader className="border-b border-rust-900/30">
                    <CardTitle className="text-lg text-rust-400 font-mono">Threat Details</CardTitle>
                  </CardHeader>
                  <CardContent className="bg-black/20">
                    {result.threats.length > 0 ? (
                      <Table>
                        <TableHeader>
                          <TableRow className="border-rust-900/30 hover:bg-zinc-800/50">
                            <TableHead className="text-rust-500 font-mono">Type</TableHead>
                            <TableHead className="text-rust-500 font-mono">Details</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {result.threats.map((threat, idx) => (
                            <TableRow key={idx} className="border-rust-900/30 hover:bg-zinc-800/50">
                              <TableCell>
                                <Badge variant="outline" className="flex items-center gap-1 w-fit bg-red-950/50 text-red-400 border-red-800 font-mono">
                                  <AlertTriangle className="h-3 w-3" /> 
                                  {threat.type}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-sm text-gray-300 font-mono">{threat.details}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : (
                      <div className="text-center py-8 text-emerald-500">
                        <p className="text-lg font-mono">✓ No threats found in this file</p>
                        <p className="text-sm mt-2 text-gray-400 font-mono">The file appears to be safe</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              <div className="flex gap-3">
                <Button className="flex items-center gap-2 bg-rust-700 hover:bg-rust-600 text-white border-rust-600 font-mono">
                  <FileText className="h-4 w-4" /> 
                  Export Report
                </Button>
                <Button variant="outline" onClick={resetScanner} className="border-rust-700 text-rust-400 hover:bg-rust-950/30 hover:text-rust-300 font-mono">
                  Scan Another File
                </Button>
              </div>
            </div>
            )
          ) : (
            <div className="text-center py-12 text-rust-600">
              <p className="font-mono">Loading scan results...</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default App;

