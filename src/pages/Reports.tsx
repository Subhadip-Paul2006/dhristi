import { useState, useEffect } from 'react';
import {
 Box, Card, CardContent, Typography, CircularProgress, Alert,
 Table, TableBody, TableCell, TableHead, TableRow, Chip, Paper, Grid,
} from '@mui/material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { intelApi } from '../api/intel';

export default function Reports() {
 const [intel, setIntel] = useState<any>(null);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState('');

 useEffect(() => {
 intelApi.getSummary()
 .then(setIntel)
 .catch((e) => setError(e.message))
 .finally(() => setLoading(false));
 }, []);

 if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}><CircularProgress /></Box>;
 if (error) return <Alert severity="error">{error}</Alert>;
 if (!intel) return null;

 const chartData = [
 { name: 'Critical', count: intel.severity_distribution.critical },
 { name: 'High', count: intel.severity_distribution.high },
 { name: 'Medium', count: intel.severity_distribution.medium },
 { name: 'Low', count: intel.severity_distribution.low },
 ];

 const severityColor: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
 critical: 'error',
 high: 'warning',
 medium: 'info',
 low: 'success',
 };

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>Reports</Typography>
 <Grid container spacing={3}>
 <Grid item xs={12} md={5}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Typography variant="h6" sx={{ color: '#e3f2fd', mb: 2 }}>Severity Distribution</Typography>
 <ResponsiveContainer width="100%" height={280}>
 <BarChart data={chartData}>
 <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
 <XAxis dataKey="name" tick={{ fill: '#90a4ae' }} axisLine={{ stroke: 'rgba(255,255,255,0.1)' }} />
 <YAxis tick={{ fill: '#90a4ae' }} axisLine={{ stroke: 'rgba(255,255,255,0.1)' }} />
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
 <Grid item xs={12} md={7}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Typography variant="h6" sx={{ color: '#e3f2fd', mb: 2 }}>CVE Summary</Typography>
 <Typography variant="body2" sx={{ color: '#90a4ae', mb: 2 }}>Total CVEs: {intel.total_cves} | Critical: {intel.critical_cves}</Typography>
 <Box sx={{ maxHeight: 350, overflow: 'auto' }}>
 <Table size="small">
 <TableHead>
 <TableRow>
 <TableCell sx={{ color: '#90a4ae' }}>CVE</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>CVSS</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Severity</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Affected Assets</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Published</TableCell>
 </TableRow>
 </TableHead>
 <TableBody>
 {(intel.top_cves || []).map((cve: any) => (
 <TableRow key={cve.cve_id}>
 <TableCell sx={{ color: '#42a5f5' }}>{cve.cve_id}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{cve.cvss_score}</TableCell>
 <TableCell><Chip label={cve.severity} color={severityColor[cve.severity] as any} size="small" /></TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{cve.affected_assets_count}</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>{new Date(cve.published_date).toLocaleDateString()}</TableCell>
 </TableRow>
 ))}
 </TableBody>
 </Table>
 </Box>
 </CardContent>
 </Card>
 </Grid>
 </Grid>
 </Box>
 );
}
