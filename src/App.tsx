import { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useQuery } from '@tanstack/react-query';
import { Button } from './components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { Progress } from './components/ui/progress';
import { Badge } from './components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from './components/ui/table';
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { FixedSizeList as List } from 'react-window';
import { Upload, FileText, AlertTriangle, Shield } from 'lucide-react';
import useScanStore from './store';

// Use window.location.hostname to automatically use the same host as the frontend
const API_BASE = `http://${window.location.hostname}:3001/api`;

interface ScanResult {
  status: 'safe' | 'unsafe' | 'suspicious' | 'scanning';
  threats: { type: string; details: string; severity: string; threatId: string }[];
  stats: {
    threatsFound: number;
    malicious: number;
    suspicious: number;
    neutral: number;
  };
  logs: string[];
  file_info?: {
    filename: string;
    size: number;
    sha256: string;
  };
  pe_analysis?: {
    headers: {
      dos_header: { e_magic: string; e_lfanew: number };
      nt_header: {
        signature: string;
        file_header: {
          machine: string;
          number_of_sections: number;
          time_date_stamp: string;
          characteristics: string[];
        };
        optional_header: {
          magic: string;
          address_of_entry_point: string;
          image_base: string;
          section_alignment: number;
          file_alignment: number;
          subsystem: string;
          dll_characteristics: string[];
        };
      };
    };
    sections: Array<{
      name: string;
      virtual_size: string;
      virtual_address: string;
      size_of_raw_data: string;
      pointer_to_raw_data: string;
      characteristics: string[];
    }>;
    imports: Array<{
      dll: string;
      functions: string[];
    }>;
    exports?: Array<{
      name: string;
      ordinal: number;
      rva: string;
    }>;
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
    xhr.upload.addEventListener('progress', e => {
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

    xhr.addEventListener('error', () => {
      setIsUploading(false);
      setErrorMessage('Upload failed. Please make sure the backend server is running.');
    });

    xhr.open('POST', `${API_BASE}/upload`);
    xhr.send(formData);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    multiple: false,
  });

  const startSSE = (id: string) => {
    const eventSource = new EventSource(`${API_BASE}/scan-status/${id}`);

    eventSource.onmessage = event => {
      try {
        const data = JSON.parse(event.data);
        setProgress(data.progress);
        setMessage(data.message);
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${data.message}`]);

        if (data.progress >= 100) {
          eventSource.close();
        }
      } catch (error) {
        console.error('Error parsing SSE data:', error);
      }
    };

    eventSource.onerror = error => {
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
        { name: 'Malicious', value: result.stats.malicious || 0 },
        { name: 'Suspicious', value: result.stats.suspicious || 0 },
        { name: 'Neutral', value: result.stats.neutral || 0 },
      ].filter(item => item.value > 0) // Only show categories with values
    : [];

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

  // Add state for expanded threat
  const [expandedThreat, setExpandedThreat] = useState<number | null>(null);

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-zinc-900 to-black p-8">
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Shield className="h-8 w-8 text-rust-500" />
              <h1 className="text-2xl font-bold text-white">PEroxide</h1>
            </div>
            <nav className="flex items-center gap-6">
              <a href="#scanner" className="text-gray-300 hover:text-rust-400 transition-colors">
                Scanner
              </a>
              <a href="#about" className="text-gray-300 hover:text-rust-400 transition-colors">
                About
              </a>
              <a href="#docs" className="text-gray-300 hover:text-rust-400 transition-colors">
                Documentation
              </a>
            </nav>
          </div>
        </div>
      </header>

      <section className="py-16 px-8">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold text-white mb-4">Advanced Malware Detection</h2>
          <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
            Scan PE files with real-time scanning progress.
          </p>
          <div className="flex justify-center gap-4 mb-8">
            <Badge className="bg-rust-900 text-rust-300">PE File Analysis</Badge>
            <Badge className="bg-rust-900 text-rust-300">Real-time Scanning</Badge>
          </div>
        </div>
      </section>

      <main className="px-8 pb-16">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            <aside className="lg:col-span-2 space-y-6">
              <Card className="bg-zinc-900 border-rust-700/50">
                <CardHeader>
                  <CardTitle className="text-rust-400">Recent Scans</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="text-sm text-gray-400">No recent scans</div>
                  </div>
                </CardContent>
              </Card>
            </aside>

            <div className="lg:col-span-8 lg:col-start-3">
              <Card className="shadow-2xl bg-zinc-900 border-rust-700/50">
                <CardHeader className="bg-gradient-to-r from-rust-800 to-rust-900 text-white rounded-t-lg border-b-2 border-rust-600">
                  <div className="flex items-center justify-center gap-3">
                    <Shield className="h-8 w-8 text-rust-400" />
                    <CardTitle className="text-3xl font-bold tracking-tight">
                      PEroxide File Scanner
                    </CardTitle>
                  </div>
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
                          <p className="text-lg font-semibold text-rust-400">
                            Drop the file here...
                          </p>
                        ) : (
                          <>
                            <p className="text-lg font-semibold text-gray-200 mb-2">
                              Drag & drop a file here, or click to select
                            </p>
                            <p className="text-sm text-gray-500 font-mono">
                              PE file analysis • Max size: 100MB
                            </p>
                          </>
                        )}
                      </div>
                      {errorMessage && (
                        <div className="mt-6 bg-red-950/50 p-4 rounded-lg border-2 border-red-800">
                          <div className="flex items-start gap-3">
                            <AlertTriangle className="h-6 w-6 text-red-400 flex-shrink-0 mt-0.5" />
                            <div className="flex-1">
                              <h3 className="text-lg font-semibold text-red-400 mb-1 font-mono">
                                Upload Rejected
                              </h3>
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
                            <span className="text-sm font-medium text-rust-400 font-mono">
                              Uploading...
                            </span>
                            <span className="text-sm font-medium text-rust-400 font-mono">
                              {Math.round(uploadProgress)}%
                            </span>
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
                          <h4 className="text-sm font-semibold text-rust-400 mb-2 font-mono">
                            File Information
                          </h4>
                          <div className="text-sm text-gray-300 font-mono space-y-1">
                            <p>
                              <span className="text-rust-500">Name:</span> {uploadedFile.name}
                            </p>
                            <p>
                              <span className="text-rust-500">Size:</span>{' '}
                              {(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB (
                              {uploadedFile.size.toLocaleString()} bytes)
                            </p>
                          </div>
                        </div>
                      )}
                      <div className="bg-zinc-800/50 p-6 rounded-lg border border-rust-800/30">
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="text-xl font-semibold text-rust-400 font-mono">
                            Scanning in Progress
                          </h3>
                          <Badge
                            variant="secondary"
                            className="text-sm px-3 py-1 bg-rust-900 text-rust-300 border-rust-700 font-mono"
                          >
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
                            <List height={240} itemCount={logs.length} itemSize={32} width="100%">
                              {LogRow}
                            </List>
                          ) : (
                            <div className="p-4 text-rust-600 text-sm font-mono">
                              Waiting for scan to start...
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ) : result ? (
                    result.status === 'scanning' ? (
                      <div className="space-y-6">
                        {(result.file_info || uploadedFile) && (
                          <div className="bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                            <h4 className="text-sm font-semibold text-rust-400 mb-2 font-mono">
                              File Information
                            </h4>
                            <div className="text-sm text-gray-300 font-mono space-y-1">
                              <p>
                                <span className="text-rust-500">Name:</span>{' '}
                                {result.file_info?.filename || uploadedFile?.name}
                              </p>
                              <p>
                                <span className="text-rust-500">Size:</span>{' '}
                                {(
                                  (result.file_info?.size || uploadedFile?.size || 0) /
                                  (1024 * 1024)
                                ).toFixed(2)}{' '}
                                MB (
                                {(
                                  result.file_info?.size ||
                                  uploadedFile?.size ||
                                  0
                                ).toLocaleString()}{' '}
                                bytes)
                              </p>
                            </div>
                          </div>
                        )}
                        <div className="bg-zinc-800/50 p-6 rounded-lg border border-rust-800/30">
                          <div className="flex items-center justify-between mb-4">
                            <h3 className="text-xl font-semibold text-rust-400 font-mono flex items-center gap-2">
                              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-rust-400"></div>
                              Scanning in Progress
                            </h3>
                            <Badge
                              variant="secondary"
                              className="text-sm px-3 py-1 bg-rust-900 text-rust-300 border-rust-700 font-mono animate-pulse"
                            >
                              SCANNING
                            </Badge>
                          </div>
                          <div className="space-y-3 mb-4">
                            <p className="text-gray-300 font-medium font-mono text-sm">
                              {message || 'Waiting for scan to start...'}
                            </p>
                          </div>
                          <div className="mt-4 bg-black/40 rounded p-3 border border-rust-900/50">
                            <div className="flex items-center justify-between text-xs text-rust-500 font-mono mb-2">
                              <span>Analysis Progress</span>
                              <span>{Math.round(progress)}%</span>
                            </div>
                            <div className="w-full bg-zinc-900 rounded-full h-2 overflow-hidden">
                              <div
                                className="h-full bg-gradient-to-r from-rust-600 to-rust-400 rounded-full"
                                style={{ width: `${progress}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-6">
                        {(result.file_info || uploadedFile) && (
                          <div className="bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                            <h4 className="text-sm font-semibold text-rust-400 mb-2 font-mono">
                              Scanned File
                            </h4>
                            <div className="text-sm text-gray-300 font-mono space-y-1">
                              <p>
                                <span className="text-rust-500">Name:</span>{' '}
                                {result.file_info?.filename || uploadedFile?.name}
                              </p>
                              <p>
                                <span className="text-rust-500">Size:</span>{' '}
                                {(
                                  (result.file_info?.size || uploadedFile?.size || 0) /
                                  (1024 * 1024)
                                ).toFixed(2)}{' '}
                                MB (
                                {(
                                  result.file_info?.size ||
                                  uploadedFile?.size ||
                                  0
                                ).toLocaleString()}{' '}
                                bytes)
                              </p>
                              {result.file_info?.sha256 && (
                                <p>
                                  <span className="text-rust-500">SHA256:</span>{' '}
                                  <span className="text-xs break-all">
                                    {result.file_info.sha256}
                                  </span>
                                </p>
                              )}
                              <p>
                                <span className="text-rust-500">Status:</span>{' '}
                                <span
                                  className={
                                    result.status === 'safe'
                                      ? 'text-emerald-400'
                                      : result.status === 'unsafe'
                                        ? 'text-red-400'
                                        : 'text-yellow-400'
                                  }
                                >
                                  {result.status === 'safe'
                                    ? 'Clean - No threats detected'
                                    : result.status === 'unsafe'
                                      ? 'Threats detected'
                                      : result.status === 'suspicious'
                                        ? 'Suspicious'
                                        : result.status}
                                </span>
                              </p>
                            </div>
                          </div>
                        )}

                        <div className="flex items-center justify-between bg-zinc-800/50 p-4 rounded-lg border border-rust-800/30">
                          <h3 className="text-2xl font-bold text-rust-400 font-mono">
                            Scan Complete
                          </h3>
                          <Badge
                            variant={
                              result.status === 'safe'
                                ? 'default'
                                : result.status === 'unsafe'
                                  ? 'destructive'
                                  : 'secondary'
                            }
                            className={`text-lg px-4 py-2 font-mono ${
                              result.status === 'safe'
                                ? 'bg-emerald-900 text-emerald-300 border-emerald-700'
                                : result.status === 'unsafe'
                                  ? 'bg-red-900 text-red-300 border-red-700'
                                  : 'bg-yellow-900 text-yellow-300 border-yellow-700'
                            }`}
                          >
                            {result.status === 'safe'
                              ? '✓ SAFE'
                              : result.status === 'unsafe'
                                ? '⚠ THREATS DETECTED'
                                : result.status === 'suspicious'
                                  ? '⚠ SUSPICIOUS'
                                  : `STATUS: ${(result.status as string).toUpperCase()}`}
                          </Badge>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                            <CardHeader className="border-b border-rust-900/30">
                              <CardTitle className="text-lg text-rust-400 font-mono">
                                Threat Statistics
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="flex justify-center bg-black/20">
                              {chartData.length > 0 ? (
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
                                    {chartData.map(item => {
                                      const colorMap: { [key: string]: string } = {
                                        Malicious: '#DC2626',
                                        Suspicious: '#FCD34D',
                                        Neutral: '#6B7280',
                                      };
                                      return (
                                        <Cell
                                          key={`cell-${item.name}`}
                                          fill={colorMap[item.name] || '#8884d8'}
                                        />
                                      );
                                    })}
                                  </Pie>
                                  <Tooltip
                                    contentStyle={{
                                      backgroundColor: '#18181b',
                                      border: '1px solid #78350f',
                                      color: '#fbbf24',
                                    }}
                                  />
                                  <Legend wrapperStyle={{ color: '#d1d5db' }} />
                                </PieChart>
                              ) : result && result.stats.threatsFound > 0 ? (
                                <div className="flex flex-col items-center justify-center h-64 text-yellow-500">
                                  <Shield className="h-24 w-24 mb-4" />
                                  <p className="text-xl font-semibold font-mono">
                                    Threats detected but severity data unavailable
                                  </p>
                                </div>
                              ) : (
                                <div className="flex flex-col items-center justify-center h-64 text-emerald-500">
                                  <Shield className="h-24 w-24 mb-4" />
                                  <p className="text-xl font-semibold font-mono">
                                    No Threats Detected
                                  </p>
                                </div>
                              )}
                            </CardContent>
                          </Card>

                          <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                            <CardHeader className="border-b border-rust-900/30">
                              <CardTitle className="text-lg text-rust-400 font-mono">
                                Threat Details
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="bg-black/20">
                              {result.threats.length > 0 ? (
                                <>
                                  <Table>
                                    <TableHeader>
                                      <TableRow className="border-rust-900/30 hover:bg-zinc-800/50">
                                        <TableHead className="text-rust-500 font-mono">
                                          Type
                                        </TableHead>
                                        <TableHead className="text-rust-500 font-mono">
                                          ThreatID
                                        </TableHead>
                                      </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                      {result.threats.map((threat, idx) => (
                                        <TableRow
                                          key={idx}
                                          className="border-rust-900/30 hover:bg-zinc-800/50 cursor-pointer transition-colors"
                                          onClick={() =>
                                            setExpandedThreat(expandedThreat === idx ? null : idx)
                                          }
                                        >
                                          <TableCell>
                                            <Badge
                                              variant="outline"
                                              className="flex items-center gap-1 w-fit bg-red-950/50 text-red-400 border-red-800 font-mono"
                                            >
                                              <AlertTriangle className="h-3 w-3" />
                                              {threat.type}
                                            </Badge>
                                          </TableCell>
                                          <TableCell className="text-sm text-gray-300 font-mono">
                                            <div className="flex items-center justify-between">
                                              <span className="font-mono text-blue-400">
                                                {threat.threatId}
                                              </span>
                                              <span
                                                className={`ml-2 text-xs transition-transform ${expandedThreat === idx ? 'rotate-180' : ''}`}
                                              >
                                                ▼
                                              </span>
                                            </div>
                                          </TableCell>
                                        </TableRow>
                                      ))}
                                    </TableBody>
                                  </Table>
                                  {expandedThreat !== null && (
                                    <div className="mt-4 p-4 bg-red-950/20 border border-red-800/50 rounded-lg">
                                      <div className="flex items-center gap-2 mb-2">
                                        <AlertTriangle className="h-4 w-4 text-red-400" />
                                        <h4 className="text-red-400 font-mono font-semibold">
                                          {result.threats[expandedThreat].type} Details
                                        </h4>
                                      </div>
                                      <p className="text-gray-300 font-mono text-sm leading-relaxed">
                                        {result.threats[expandedThreat].details}
                                      </p>
                                      {result.threats[expandedThreat].severity && (
                                        <div className="mt-2">
                                          <Badge
                                            variant="outline"
                                            className="bg-yellow-950/50 text-yellow-400 border-yellow-800 font-mono text-xs"
                                          >
                                            Severity: {result.threats[expandedThreat].severity}
                                          </Badge>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </>
                              ) : (
                                <div className="text-center py-8 text-emerald-500">
                                  <p className="text-lg font-mono">
                                    ✓ No threats found in this file
                                  </p>
                                  <p className="text-sm mt-2 text-gray-400 font-mono">
                                    The file appears to be safe
                                  </p>
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        </div>

                        {/* Static Analysis Section */}
                        <div className="mt-8 space-y-6">
                          <div className="flex items-center gap-3 mb-4">
                            <FileText className="h-6 w-6 text-rust-400" />
                            <h3 className="text-2xl font-bold text-rust-400 font-mono">
                              Static Analysis
                            </h3>
                          </div>

                          {/* PE Headers */}
                          <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                            <CardHeader className="border-b border-rust-900/30">
                              <CardTitle className="text-lg text-rust-400 font-mono">
                                PE Headers
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="bg-black/20 p-6">
                              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                {/* DOS Header */}
                                <div className="space-y-3">
                                  <h4 className="text-sm font-semibold text-rust-300 font-mono border-b border-rust-900/30 pb-2">
                                    DOS Header
                                  </h4>
                                  <div className="space-y-2 text-sm font-mono">
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Magic:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.dos_header.e_magic || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">NT Header Offset:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.dos_header.e_lfanew
                                          ? `0x${result.pe_analysis.headers.dos_header.e_lfanew.toString(16).toUpperCase()}`
                                          : 'N/A'}
                                      </span>
                                    </div>
                                  </div>
                                </div>

                                {/* File Header */}
                                <div className="space-y-3">
                                  <h4 className="text-sm font-semibold text-rust-300 font-mono border-b border-rust-900/30 pb-2">
                                    File Header
                                  </h4>
                                  <div className="space-y-2 text-sm font-mono">
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Machine:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.file_header
                                          .machine || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Sections:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.file_header
                                          .number_of_sections || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Timestamp:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.file_header
                                          .time_date_stamp || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="space-y-1">
                                      <span className="text-gray-400 text-xs">
                                        Characteristics:
                                      </span>
                                      <div className="flex flex-wrap gap-1">
                                        {result.pe_analysis?.headers.nt_header.file_header.characteristics?.map(
                                          (char, idx) => (
                                            <Badge
                                              key={idx}
                                              variant="outline"
                                              className="text-xs bg-blue-950/50 text-blue-300 border-blue-800"
                                            >
                                              {char}
                                            </Badge>
                                          )
                                        ) || (
                                          <Badge
                                            variant="outline"
                                            className="text-xs bg-gray-950/50 text-gray-400 border-gray-700"
                                          >
                                            N/A
                                          </Badge>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* Optional Header */}
                                <div className="space-y-3 lg:col-span-2">
                                  <h4 className="text-sm font-semibold text-rust-300 font-mono border-b border-rust-900/30 pb-2">
                                    Optional Header
                                  </h4>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm font-mono">
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Magic:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.optional_header
                                          .magic || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Entry Point:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.optional_header
                                          .address_of_entry_point || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Image Base:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.optional_header
                                          .image_base || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Subsystem:</span>
                                      <span className="text-blue-400">
                                        {result.pe_analysis?.headers.nt_header.optional_header
                                          .subsystem || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="space-y-1 md:col-span-2">
                                      <span className="text-gray-400 text-xs">
                                        DLL Characteristics:
                                      </span>
                                      <div className="flex flex-wrap gap-1">
                                        {result.pe_analysis?.headers.nt_header.optional_header.dll_characteristics?.map(
                                          (char, idx) => (
                                            <Badge
                                              key={idx}
                                              variant="outline"
                                              className="text-xs bg-green-950/50 text-green-300 border-green-800"
                                            >
                                              {char}
                                            </Badge>
                                          )
                                        ) || (
                                          <Badge
                                            variant="outline"
                                            className="text-xs bg-gray-950/50 text-gray-400 border-gray-700"
                                          >
                                            N/A
                                          </Badge>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </CardContent>
                          </Card>

                          {/* Sections Table */}
                          <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                            <CardHeader className="border-b border-rust-900/30">
                              <CardTitle className="text-lg text-rust-400 font-mono">
                                Sections ({result.pe_analysis?.sections?.length || 0})
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="bg-black/20">
                              {result.pe_analysis?.sections &&
                              result.pe_analysis.sections.length > 0 ? (
                                <Table>
                                  <TableHeader>
                                    <TableRow className="border-rust-900/30">
                                      <TableHead className="text-rust-500 font-mono">
                                        Name
                                      </TableHead>
                                      <TableHead className="text-rust-500 font-mono">
                                        Virtual Size
                                      </TableHead>
                                      <TableHead className="text-rust-500 font-mono">
                                        Virtual Address
                                      </TableHead>
                                      <TableHead className="text-rust-500 font-mono">
                                        Raw Size
                                      </TableHead>
                                      <TableHead className="text-rust-500 font-mono">
                                        Characteristics
                                      </TableHead>
                                    </TableRow>
                                  </TableHeader>
                                  <TableBody>
                                    {result.pe_analysis.sections.map((section, idx) => (
                                      <TableRow key={idx} className="border-rust-900/30">
                                        <TableCell className="font-mono text-blue-400">
                                          {section.name}
                                        </TableCell>
                                        <TableCell className="font-mono text-gray-300">
                                          {section.virtual_size}
                                        </TableCell>
                                        <TableCell className="font-mono text-gray-300">
                                          {section.virtual_address}
                                        </TableCell>
                                        <TableCell className="font-mono text-gray-300">
                                          {section.size_of_raw_data}
                                        </TableCell>
                                        <TableCell>
                                          <div className="flex flex-wrap gap-1">
                                            {section.characteristics
                                              .slice(0, 3)
                                              .map((char, charIdx) => (
                                                <Badge
                                                  key={charIdx}
                                                  variant="outline"
                                                  className="text-xs bg-purple-950/50 text-purple-300 border-purple-800"
                                                >
                                                  {char}
                                                </Badge>
                                              ))}
                                            {section.characteristics.length > 3 && (
                                              <Badge
                                                variant="outline"
                                                className="text-xs bg-gray-950/50 text-gray-400 border-gray-700"
                                              >
                                                +{section.characteristics.length - 3}
                                              </Badge>
                                            )}
                                          </div>
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              ) : (
                                <div className="text-center py-8 text-gray-500">
                                  <p className="font-mono">N/A - No section data available</p>
                                </div>
                              )}
                            </CardContent>
                          </Card>

                          {/* Import Address Table */}
                          <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                            <CardHeader className="border-b border-rust-900/30">
                              <CardTitle className="text-lg text-rust-400 font-mono">
                                Imports
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="bg-black/20">
                              {result.pe_analysis?.imports &&
                              result.pe_analysis.imports.length > 0 ? (
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                  {result.pe_analysis.imports.map((import_dll, idx) => (
                                    <div
                                      key={idx}
                                      className="bg-zinc-900/50 p-4 rounded-lg border border-rust-900/30"
                                    >
                                      <h4 className="text-sm font-semibold text-rust-300 font-mono mb-2">
                                        {import_dll.dll}
                                      </h4>
                                      <div className="space-y-1">
                                        {import_dll.functions.slice(0, 5).map((func, funcIdx) => (
                                          <div
                                            key={funcIdx}
                                            className="text-xs font-mono text-gray-400"
                                          >
                                            {func}
                                          </div>
                                        ))}
                                        {import_dll.functions.length > 5 && (
                                          <div className="text-xs text-gray-500 font-mono">
                                            ... and {import_dll.functions.length - 5} more
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="text-center py-8 text-gray-500">
                                  <p className="font-mono">N/A - No import data available</p>
                                </div>
                              )}
                            </CardContent>
                          </Card>

                          {/* Exports (if present) */}
                          {result.pe_analysis?.exports && result.pe_analysis.exports.length > 0 ? (
                            <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                              <CardHeader className="border-b border-rust-900/30">
                                <CardTitle className="text-lg text-rust-400 font-mono">
                                  Exports ({result.pe_analysis.exports.length})
                                </CardTitle>
                              </CardHeader>
                              <CardContent className="bg-black/20">
                                <Table>
                                  <TableHeader>
                                    <TableRow className="border-rust-900/30">
                                      <TableHead className="text-rust-500 font-mono">
                                        Ordinal
                                      </TableHead>
                                      <TableHead className="text-rust-500 font-mono">
                                        Name
                                      </TableHead>
                                      <TableHead className="text-rust-500 font-mono">RVA</TableHead>
                                    </TableRow>
                                  </TableHeader>
                                  <TableBody>
                                    {result.pe_analysis.exports.map((export_item, idx) => (
                                      <TableRow key={idx} className="border-rust-900/30">
                                        <TableCell className="font-mono text-blue-400">
                                          {export_item.ordinal}
                                        </TableCell>
                                        <TableCell className="font-mono text-gray-300">
                                          {export_item.name}
                                        </TableCell>
                                        <TableCell className="font-mono text-gray-300">
                                          {export_item.rva}
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </CardContent>
                            </Card>
                          ) : (
                            <Card className="shadow-lg bg-zinc-800/50 border-rust-800/30">
                              <CardHeader className="border-b border-rust-900/30">
                                <CardTitle className="text-lg text-rust-400 font-mono">
                                  Exports
                                </CardTitle>
                              </CardHeader>
                              <CardContent className="bg-black/20">
                                <div className="text-center py-8 text-gray-500">
                                  <p className="font-mono">N/A - No export data available</p>
                                </div>
                              </CardContent>
                            </Card>
                          )}
                        </div>

                        <div className="flex gap-3">
                          <Button className="flex items-center gap-2 bg-rust-700 hover:bg-rust-600 text-white border-rust-600 font-mono">
                            <FileText className="h-4 w-4" />
                            Export Report
                          </Button>
                          <Button
                            variant="outline"
                            onClick={resetScanner}
                            className="border-rust-800/50 text-gray-400 hover:bg-zinc-800/50 hover:text-gray-300 hover:border-rust-700 font-mono"
                          >
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
          </div>
        </div>
      </main>

      <footer className="border-t border-zinc-800 bg-zinc-950/50">
        <div className="max-w-7xl mx-auto px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="h-6 w-6 text-rust-500" />
                <span className="font-bold text-white">PEroxide</span>
              </div>
              <p className="text-gray-400 text-sm">Advanced malware detection for PE files.</p>
            </div>
            <div>
              <h3 className="font-semibold text-white mb-4">Resources</h3>
              <ul className="space-y-2 text-sm">
                <li>
                  <a href="#" className="text-gray-400 hover:text-rust-400">
                    Documentation
                  </a>
                </li>
                <li>
                  <a href="#" className="text-gray-400 hover:text-rust-400">
                    API Reference
                  </a>
                </li>
                <li>
                  <a href="#" className="text-gray-400 hover:text-rust-400">
                    Security
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold text-white mb-4">Support</h3>
              <ul className="space-y-2 text-sm">
                <li>
                  <a href="#" className="text-gray-400 hover:text-rust-400">
                    GitHub
                  </a>
                </li>
                <li>
                  <a href="#" className="text-gray-400 hover:text-rust-400">
                    Issues
                  </a>
                </li>
                <li>
                  <a href="#" className="text-gray-400 hover:text-rust-400">
                    Contact
                  </a>
                </li>
              </ul>
            </div>
          </div>
          <div className="border-t border-zinc-800 mt-8 pt-8 text-center text-sm text-gray-500">
            <p>© 2024 PEroxide. Built with Rust and React.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};
export default App;
