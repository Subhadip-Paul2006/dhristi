import { useState, useEffect } from 'react';
import {
 Box, Card, CardContent, Table, TableBody, TableCell, TableHead, TableRow,
 Chip, Button, Dialog, DialogTitle, DialogContent, Typography, CircularProgress, Alert,
 TableContainer, Paper, IconButton,
} from '@mui/material';
import { assetsApi, type Asset, type Finding } from '../api/assets';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { DataGrid } from '@mui/x-data-grid';

const severityColor: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
 critical: 'error',
 high: 'warning',
 medium: 'info',
 low: 'success',
};

export default function Assets() {
 const [assets, setAssets] = useState<Asset[]>([]);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState('');
 const [selected, setSelected] = useState<Asset | null>(null);
 const [detailOpen, setDetailOpen] = useState(false);

 useEffect(() => {
 assetsApi.list()
 .then(setAssets)
 .catch((e) => setError(e.message))
 .finally(() => setLoading(false));
 }, []);

 const openDetail = (a: Asset) => {
 setSelected(a);
 setDetailOpen(true);
 };

 const columns = [
 { field: 'ip_address', headerName: 'IP Address', width: 150 },
 { field: 'hostname', headerName: 'Hostname', width: 200 },
 { field: 'zone', headerName: 'Zone', width: 140 },
 { field: 'asset_type', headerName: 'Type', width: 140 },
 { field: 'risk_score', headerName: 'Risk Score', width: 130, type: 'number' },
 {
 field: 'is_crown_jewel',
 headerName: 'Crown Jewel',
 width: 130,
 renderCell: (params: any) => params.value ? <Chip label="Yes" color="error" size="small" /> : <Chip label="No" size="small" color="default" />,
 },
 {
 field: 'actions',
 headerName: 'Actions',
 width: 120,
 sortable: false,
 renderCell: (params: any) => (
 <IconButton color="primary" size="small" onClick={() => openDetail(params.row)}>
 <VisibilityIcon fontSize="small" />
 </IconButton>
 ),
 },
 ];

 if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}><CircularProgress /></Box>;
 if (error) return <Alert severity="error">{error}</Alert>;

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>Assets</Typography>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Box sx={{ height: 600 }}>
 <DataGrid
 rows={assets}
 columns={columns}
 pageSizeOptions={[10, 25, 50]}
 disableRowSelectionOnClick
 getRowId={(row) => row.id}
 sx={{
 background: 'transparent',
 '& .MuiDataGrid-columnHeaders': { background: '#0a1929', color: '#42a5f5' },
 '& .MuiDataGrid-cell': { color: '#e3f2fd' },
 '& .MuiDataGrid-row': { background: '#0d2137', '&:hover': { background: '#1a2f45' } },
 }}
 />
 </Box>
 </CardContent>
 </Card>

 <Dialog open={detailOpen} onClose={() => setDetailOpen(false)} maxWidth="md" fullWidth>
 <DialogTitle sx={{ color: '#e3f2fd', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
 {selected?.hostname} — {selected?.ip_address}
 </DialogTitle>
 <DialogContent sx={{ mt: 2 }}>
 {selected && (
 <Box>
 <Typography variant="h6" sx={{ color: '#42a5f5', mb: 1 }}>Services</Typography>
 <Table size="small">
 <TableHead>
 <TableRow>
 <TableCell sx={{ color: '#90a4ae' }}>Name</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Port</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Protocol</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Version</TableCell>
 </TableRow>
 </TableHead>
 <TableBody>
 {(selected.services || []).map((svc) => (
 <TableRow key={svc.id}>
 <TableCell sx={{ color: '#e3f2fd' }}>{svc.name}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{svc.port}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{svc.protocol}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{svc.version || '-'}</TableCell>
 </TableRow>
 ))}
 </TableBody>
 </Table>

 <Typography variant="h6" sx={{ color: '#42a5f5', mt: 3, mb: 1 }}>Findings</Typography>
 <Table size="small">
 <TableHead>
 <TableRow>
 <TableCell sx={{ color: '#90a4ae' }}>Title</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Severity</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>CVE</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>CVSS</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Status</TableCell>
 </TableRow>
 </TableHead>
 <TableBody>
 {(selected.findings || []).map((f: Finding) => (
 <TableRow key={f.id}>
 <TableCell sx={{ color: '#e3f2fd' }}>{f.title}</TableCell>
 <TableCell><Chip label={f.severity} color={severityColor[f.severity] as any} size="small" /></TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{f.cve_id || '-'}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{f.cvss_score ?? '-'}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{f.status}</TableCell>
 </TableRow>
 ))}
 </TableBody>
 </Table>
 </Box>
 )}
 </DialogContent>
 </Dialog>
 </Box>
 );
}
