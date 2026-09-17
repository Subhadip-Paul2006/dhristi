import { useState } from 'react';
import {
 Box, Card, CardContent, Typography, TextField, Button, CircularProgress,
 Alert, Chip, Paper,
} from '@mui/material';
import { urltrustApi } from '../api/urltrust';

export default function URLTrust() {
 const [url, setUrl] = useState('');
 const [result, setResult] = useState<any>(null);
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState('');

 const handleAnalyze = async (e: React.FormEvent) => {
 e.preventDefault();
 setLoading(true);
 setError('');
 setResult(null);
 try {
 const res = await urltrustApi.analyze(url);
 setResult(res);
 } catch (e: any) {
 setError(e.message);
 } finally {
 setLoading(false);
 }
 };

 const riskColor = result ? (result.risk_level === 'safe' ? 'success' : result.risk_level === 'malicious' ? 'error' : 'warning') : 'default';

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>URL Trust Analysis</Typography>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Box component="form" onSubmit={handleAnalyze}>
 <TextField
 label="URL to analyze"
 fullWidth
 value={url}
 onChange={(e) => setUrl(e.target.value)}
 placeholder="https://example.com"
 required
 />
 <Button type="submit" variant="contained" disabled={loading} sx={{ mt: 2, background: 'linear-gradient(90deg, #1565c0, #42a5f5)', '&:hover': { background: 'linear-gradient(90deg, #0d47a1, #1565c0)' } }}>
 {loading ? 'Analyzing...' : 'Analyze URL'}
 </Button>
 </Box>
 </CardContent>
 </Card>
 {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
 {result && (
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)', mt: 3 }}>
 <CardContent>
 <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
 <Box sx={{ flex: '1 1 300px' }}>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Trust Score</Typography>
 <Typography variant="h3" sx={{ color: '#42a5f5', fontWeight: 700 }}>{result.trust_score}/100</Typography>
 <Chip label={result.risk_level} color={riskColor} sx={{ mt: 1 }} />
 </Box>
 <Box sx={{ flex: '2 1 400px' }}>
 <Typography variant="overline" sx={{ color: '#90a4ae' }}>Threat Indicators</Typography>
 <Box sx={{ mt: 1 }}>
 {result.threat_indicators.length > 0 ? result.threat_indicators.map((t: string) => <Chip key={t} label={t} size="small" sx={{ mr: 0.5, mb: 0.5 }} color="error" />) : <Typography variant="body2" sx={{ color: '#4caf50' }}>No threats detected</Typography>}
 </Box>
 </Box>
 </Box>
 <Box mt={3}>
 <Typography variant="h6" sx={{ color: '#42a5f5', mb: 1 }}>Recommendation</Typography>
 <Typography variant="body2" sx={{ color: '#e3f2fd' }}>{result.recommendation}</Typography>
 </Box>
 <Box mt={2}>
 <Typography variant="h6" sx={{ color: '#42a5f5', mb: 1 }}>Categories</Typography>
 <Box>
 {result.categories.map((c: string) => <Chip key={c} label={c} size="small" sx={{ mr: 0.5, mb: 0.5, background: '#1565c0', color: '#e3f2fd' }} />)}
 </Box>
 </Box>
 </CardContent>
 </Card>
 )}
 </Box>
 );
}
