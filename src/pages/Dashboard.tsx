import { useState, useEffect } from 'react';
import {
 Box, Grid, Card, CardContent, Typography, Chip, CircularProgress, Alert,
 Table, TableBody, TableCell, TableHead, TableRow,
} from '@mui/material';
import {
 TrendingUp as ExposureIcon,
 BugReport as FindingsIcon,
 Security as CriticalIcon,
} from '@mui/icons-material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { dashboardApi, type DashboardSummary } from '../api/dashboard';
import { XGrid } from '@mui/x-data-grid';

const severityData = [
 { name: 'Critical', value: 0, color: '#f44336' },
 { name: 'High', value: 0, color: '#ff9800' },
 { name: 'Medium', value: 0, color: '#ffeb3b' },
 { name: 'Low', value: 0, color: '#4caf50' },
];

export default function Dashboard() {
 const [data, setData] = useState<DashboardSummary | null>(null);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState('');

 useEffect(() => {
 dashboardApi.getSummary()
 .then(setData)
 .catch((e) => setError(e.message))
 .finally(() => setLoading(false));
 }, []);

 if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}><CircularProgress /></Box>;
 if (error) return <Alert severity="error">{error}</Alert>;
 if (!data) return null;

 const chartData = [
 { name: 'Critical', count: data.severity_distribution.critical },
 { name: 'High', count: data.severity_distribution.high },
 { name: 'Medium', count: data.severity_distribution.medium },
 { name: 'Low', count: data.severity_distribution.low },
 ];

 const columns = [
 { field: 'zone', headerName: 'Zone', width: 180 },
 { field: 'asset_count', headerName: 'Assets', type: 'number', width: 120 },
 { field: 'avg_risk_score', headerName: 'Avg Risk Score', type: 'number', width: 160 },
 { field: 'open_findings', headerName: 'Open Findings', type: 'number', width: 160 },
 { field: 'critical_findings', headerName: 'Critical', type: 'number', width: 140 },
 ];

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>Dashboard</Typography>
 <Grid container spacing={3}>
 <Grid item xs={12} sm={6} md={4}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
 <Box>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Total Exposure</Typography>
 <Typography variant="h5" sx={{ color: '#f44336', fontWeight: 700, mt: 0.5 }}>
 ${data.total_exposure_usd.toLocaleString()}
 </Typography>
 </Box>
 <ExposureIcon sx={{ fontSize: 48, color: 'rgba(244,67,54,0.2)' }} />
 </Box>
 </CardContent>
 </Card>
 </Grid>
 <Grid item xs={12} sm={6} md={4}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
 <Box>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Open Findings</Typography>
 <Typography variant="h5" sx={{ color: '#ff9800', fontWeight: 700, mt: 0.5 }}>{data.open_findings}</Typography>
 </Box>
 <FindingsIcon sx={{ fontSize: 48, color: 'rgba(255,152,0,0.2)' }} />
 </Box>
 </CardContent>
 </Card>
 </Grid>
 <Grid item xs={12} sm={6} md={4}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
 <Box>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Critical Assets</Typography>
 <Typography variant="h5" sx={{ color: '#f44336', fontWeight: 700, mt: 0.5 }}>{data.critical_assets}</Typography>
 </Box>
 <CriticalIcon sx={{ fontSize: 48, color: 'rgba(244,67,54,0.2)' }} />
 </Box>
 </CardContent>
 </Card>
 </Grid>

 <Grid item xs={12} md={8}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Typography variant="h6" sx={{ color: '#e3f2fd', mb: 2 }}>Severity Distribution</Typography>
 <ResponsiveContainer width="100%" height={280}>
 <BarChart data={chartData}>
 <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
 <XAxis dataKey="name" tick={{ fill: '#90a4ae', fontSize: 12 }} axisLine={{ stroke: 'rgba(255,255,255,0.1)' }} />
 <YAxis tick={{ fill: '#90a4ae', fontSize: 12 }} axisLine={{ stroke: 'rgba(255,255,255,0.1)' }} />
 <Tooltip contentStyle={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.3)', borderRadius: 8 }} />
 <Bar dataKey="count" radius={[4, 4, 0, 0]}>
 {chartData.map((entry) => (
 <Bar key={entry.name} dataKey="count" fill={entry.color} />
 ))}
 </Bar>
 </BarChart>
 </ResponsiveContainer>
 </CardContent>
 </Card>
 </Grid>

 <Grid item xs={12} md={4}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)', height: '100%' }}>
 <CardContent>
 <Typography variant="h6" sx={{ color: '#e3f2fd', mb: 2 }}>Top Attack Path</Typography>
 <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
 <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
 <Typography variant="body2" sx={{ color: '#90a4ae' }}>Name</Typography>
 <Typography variant="body2" sx={{ color: '#e3f2fd', fontWeight: 600 }}>{data.top_attack_path.name}</Typography>
 </Box>
 <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
 <Typography variant="body2" sx={{ color: '#90a4ae' }}>Risk Score</Typography>
 <Chip label={data.top_attack_path.risk_score} size="small" color="error" />
 </Box>
 <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
 <Typography variant="body2" sx={{ color: '#90a4ae' }}>Exposure</Typography>
 <Typography variant="body2" sx={{ color: '#f44336', fontWeight: 600 }}>
 ${data.top_attack_path.estimated_exposure_usd.toLocaleString()}
 </Typography>
 </Box>
 <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
 <Typography variant="body2" sx={{ color: '#90a4ae' }}>Target</Typography>
 <Typography variant="body2" sx={{ color: '#e3f2fd' }}>{data.top_attack_path.target_asset}</Typography>
 </Box>
 </Box>
 </CardContent>
 </Card>
 </Grid>

 <Grid item xs={12}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Typography variant="h6" sx={{ color: '#e3f2fd', mb: 2 }}>Zone Summary</Typography>
 <Box sx={{ height: 400 }}>
 <XGrid
 rows={data.zone_summary.map((z, i) => ({ ...z, id: i }))}
 columns={columns}
 pageSizeOptions={[10, 25, 50]}
 disableSelectionOnClick
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
 </Grid>
 </Grid>
 </Box>
 );
}
