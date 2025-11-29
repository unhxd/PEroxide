import { create } from 'zustand';

interface ScanStore {
  scanId: string | null;
  setScanId: (id: string | null) => void;
  progress: number;
  setProgress: (progress: number) => void;
  message: string;
  setMessage: (message: string) => void;
}

const useScanStore = create<ScanStore>(set => ({
  scanId: null,
  setScanId: id => set({ scanId: id }),
  progress: 0,
  setProgress: progress => set({ progress }),
  message: '',
  setMessage: message => set({ message }),
}));

export default useScanStore;
