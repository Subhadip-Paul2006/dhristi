import { useState, useEffect } from 'react';
import {
 Box, Card, CardContent, Typography, CircularProgress, Alert, Table, TableBody,
 TableCell, TableHead, TableRow, Chip, Tabs, Tab, Paper, Grid,
} from '@mui/material';
import { liveApi, type DeviceInfo, type ThreatEvent } from '../api/live';

export default function Live() {
 const [tab, setTab] = useState(0);
 const [devices, setDevices] = useState<DeviceInfo[]>([]);
 const [threats, setThreats] = useState<ThreatEvent[]>([]);
 const [batch, setBatch] = useState<any>(null);
 const [coverage, setCoverage] = useState<any>(null);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState('');

 useEffect(() => {
 Promise.all([liveApi.getDevices(), liveApi.getThreats(), liveApi.getDeviceBatch(), liveApi.getCoverage()])
 .then(([devicesRes, threatsRes, batchRes, coverageRes]) => {
 setDevices(devicesRes);
 setThreats(threatsRes);
 setBatch(batchRes);
 setCoverage(coverageRes);
 })
 .catch((e) => setError(e.message))
 .finally(() => setLoading(false));
 }, []);

 if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}><CircularProgress /></Box>;
 if (error) return <Alert severity="error">{error}</Alert>;

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>Live Monitoring</Typography>
 <Grid container spacing={3}>
 <Grid item xs={12} sm={6}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Device Batch</Typography>
 <Typography variant="h4" sx={{ color: '#42a5f5', mt: 1 }}>
 {batch?.online_devices}/{batch?.total_devices} online
 </Typography>
 <Typography variant="body2" sx={{ color: '#90a4ae', mt: 1 }}>
 Zones: {JSON.stringify(batch?.zones || {})}
 </Typography>
 </CardContent>
 </Card>
 </Grid>
 <Grid item xs={12} sm={6}>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Coverage</Typography>
 <Typography variant="h4" sx={{ color: '#4caf50', mt: 1 }}>
 {coverage?.coverage_percentage}%
 </Typography>
 <Typography variant="body2" sx={{ color: '#90a4ae', mt: 1 }}>
 {coverage?.monitored_assets}/{coverage?.total_assets} monitored
 </Typography>
 {coverage?.gaps?.length > 0 && (
 <Box mt={1}>
 {coverage.gaps.map((g: string, i: number) => <Chip key={i} label={g} size="small" sx={{ mr: 0.5, mb: 0.5 }} color="warning" />)}
 </Box>
 )}
 </CardContent>
 </Card>
 </Grid>
 </Grid>

 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)', mt: 3 }}>
 <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
 <Tabs value={tab} onChange={(_, v) => setTab(v)} textColor="primary" indicatorColor="primary">
 <Tab label={`Devices (${devices.length})`} />
 <Tab label={`Threats (${threats.length})`} />
 </Tabs>
 </Box>
 <CardContent>
 {tab === 0 && (
 <TableContainer component={Paper} sx={{ background: 'transparent' }}>
 <Table size="small">
 <TableHead>
 <TableRow>
 <TableCell sx={{ color: '#90a4ae' }}>IP</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Hostname</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Zone</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Type</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Risk</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Status</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Last Seen</TableCell>
 </TableRow>
 </TableHead>
 <TableBody>
 {devices.map((d) => (
 <TableRow key={d.id}>
 <TableCell sx={{ color: '#e3f2fd' }}>{d.ip_address}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{d.hostname}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{d.zone}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{d.asset_type}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{d.risk_score}</TableCell>
 <TableCell><Chip label={d.is_online ? 'Online' : 'Offline'} color={d.is_online ? 'success' : 'default'} size="small" /></TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>{new Date(d.last_seen).toLocaleString()}</TableCell>
 </TableRow>
 ))}
 </TableBody>
 </Table>
 </TableContainer>
 )}
 {tab === 1 && (
 <TableContainer component={Paper} sx={{ background: 'transparent' }}>
 <Table size="small">
 <TableHead>
 <TableRow>
 <TableCell sx={{ color: '#90a4ae' }}>Title</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Severity</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Source IP</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Detected</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Status</TableCell>
 </TableRow>
 </TableHead>
 <TableBody>
 {threats.map((t) => (
 <TableRow key={t.id}>
 <TableCell sx={{ color: '#e3f2fd' }}>{t.title}</TableCell>
 <TableCell><Chip label={t.severity} color={t.severity === 'critical' ? 'error' : t.severity === 'high' ? 'warning' : 'info'} size="small" /></TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{t.source_ip || '-'}</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>{new Date(t.detected_at).toLocaleString()}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{t.status}</TableCell>
 </TableRow>
 ))}
 </TableBody>
 </Table>
 </TableContainer>
 )}
 </CardContent>
 </Card>
 </Box>
 );
}
