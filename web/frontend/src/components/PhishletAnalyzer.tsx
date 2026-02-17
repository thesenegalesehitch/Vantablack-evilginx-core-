import React, { useState } from 'react';
import { Card, Upload, Button, Table, Tag, Alert, Progress, Tabs, Select, Input } from 'antd';
import { 
  SecurityScanOutlined, 
  UploadOutlined, 
  BugOutlined, 
  DownloadOutlined,
  EyeOutlined,
  WarningOutlined
} from '@ant-design/icons';
import type { UploadProps } from 'antd';

const { TabPane } = Tabs;
const { Option } = Select;

interface AnalysisResult {
  phishlet_name: string;
  risk_score: number;
  auth_subdomains: string[];
  login_paths: string[];
  anti_detection: string[];
  data_extraction: any;
  signatures_generated: number;
  patterns_found: number;
}

const PhishletAnalyzer: React.FC = () => {
  const [analysisResults, setAnalysisResults] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedPhishlet, setSelectedPhishlet] = useState<string>('');

  const uploadProps: UploadProps = {
    name: 'file',
    action: '/api/analyzer/upload',
    onChange(info) {
      if (info.file.status === 'uploading') {
        setLoading(true);
      }
      if (info.file.status === 'done') {
        setLoading(false);
        // Simulate analysis result
        setAnalysisResults({
          phishlet_name: 'twitter',
          risk_score: 7.8,
          auth_subdomains: ['mobile.twitter.com', 'api.twitter.com'],
          login_paths: ['/login', '/sessions/create'],
          anti_detection: ['user_agent_rotation', 'timing_variation'],
          data_extraction: { 'login_form': ['username', 'password', 'csrf_token'] },
          signatures_generated: 12,
          patterns_found: 5
        });
      }
    },
  };

  const signatureColumns = [
    { title: 'Type', dataIndex: 'type', key: 'type' },
    { title: 'Pattern', dataIndex: 'pattern', key: 'pattern' },
    { title: 'Severity', dataIndex: 'severity', key: 'severity' },
    { title: 'Tool', dataIndex: 'tool', key: 'tool' }
  ];

  const signatureData = [
    { key: '1', type: 'YARA', pattern: 'twitter_auth_flow', severity: 'High', tool: 'Malware Detection' },
    { key: '2', type: 'Snort', pattern: 'twitter_login_post', severity: 'Medium', tool: 'Network IDS' },
    { key: '3', type: 'Regex', pattern: 'twitter_domain', severity: 'Low', tool: 'Log Analysis' },
    { key: '4', type: 'IOC', pattern: 'twitter.com/login', severity: 'Critical', tool: 'Threat Intel' }
  ];

  const patternColumns = [
    { title: 'Pattern', dataIndex: 'pattern', key: 'pattern' },
    { title: 'Description', dataIndex: 'description', key: 'description' },
    { title: 'MITRE Technique', dataIndex: 'mitre', key: 'mitre' },
    { title: 'Confidence', dataIndex: 'confidence', key: 'confidence' }
  ];

  const patternData = [
    { key: '1', pattern: 'Credential Harvesting', description: 'Standard login form attack', mitre: 'T1056', confidence: '85%' },
    { key: '2', pattern: 'Session Hijacking', description: 'Cookie theft attempt', mitre: 'T1550', confidence: '72%' },
    { key: '3', pattern: 'Reverse Proxy', description: 'Evilginx-style proxy', mitre: 'T1071', confidence: '94%' }
  ];

  const getRiskColor = (score: number) => {
    if (score >= 8) return '#ff4d4f';
    if (score >= 5) return '#faad14';
    return '#52c41a';
  };

  const getRiskLevel = (score: number) => {
    if (score >= 8) return 'Critical';
    if (score >= 5) return 'Medium';
    return 'Low';
  };

  return (
    <div className="phishlet-analyzer">
      <div style={{ marginBottom: 24 }}>
        <h2><SecurityScanOutlined /> Phishlet Analyzer</h2>
        <p>Automatic reverse engineering and threat intelligence generation</p>
      </div>

      {/* Upload Section */}
      <Card title="Upload Phishlet" style={{ marginBottom: 24 }}>
        <Upload.Dragger {...uploadProps}>
          <p className="ant-upload-drag-icon">
            <UploadOutlined style={{ fontSize: 48, color: '#1890ff' }} />
          </p>
          <p className="ant-upload-text">Click or drag phishlet file to this area to upload</p>
          <p className="ant-upload-hint">Support for .yaml phishlet files only</p>
        </Upload.Dragger>
      </Card>

      {analysisResults && (
        <>
          {/* Analysis Results */}
          <Card title="Analysis Results" style={{ marginBottom: 24 }}>
            <Row gutter={[16, 16]}>
              <Col xs={24} md={8}>
                <Card size="small">
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 48, color: getRiskColor(analysisResults.risk_score) }}>
                      {analysisResults.risk_score}
                    </div>
                    <div style={{ fontSize: 16, fontWeight: 'bold' }}>
                      Risk Score
                    </div>
                    <Tag color={getRiskColor(analysisResults.risk_score)}>
                      {getRiskLevel(analysisResults.risk_score)}
                    </Tag>
                  </div>
                </Card>
              </Col>
              <Col xs={24} md={8}>
                <Card size="small">
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 48, color: '#1890ff' }}>
                      {analysisResults.signatures_generated}
                    </div>
                    <div style={{ fontSize: 16, fontWeight: 'bold' }}>
                      Signatures Generated
                    </div>
                    <div style={{ color: '#666' }}>YARA, Snort, Regex, IOC</div>
                  </div>
                </Card>
              </Col>
              <Col xs={24} md={8}>
                <Card size="small">
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 48, color: '#722ed1' }}>
                      {analysisResults.patterns_found}
                    </div>
                    <div style={{ fontSize: 16, fontWeight: 'bold' }}>
                      Attack Patterns
                    </div>
                    <div style={{ color: '#666' }}>MITRE ATT&CK mapped</div>
                  </div>
                </Card>
              </Col>
            </Row>

            {/* Detailed Analysis */}
            <div style={{ marginTop: 24 }}>
              <h4>Technical Details</h4>
              <Row gutter={[16, 16]}>
                <Col xs={24} md={12}>
                  <div style={{ marginBottom: 16 }}>
                    <strong>Authentication Subdomains:</strong>
                    <div>
                      {analysisResults.auth_subdomains.map((subdomain, index) => (
                        <Tag key={index} color="blue">{subdomain}</Tag>
                      ))}
                    </div>
                  </div>
                  <div style={{ marginBottom: 16 }}>
                    <strong>Login Paths:</strong>
                    <div>
                      {analysisResults.login_paths.map((path, index) => (
                        <Tag key={index} color="green">{path}</Tag>
                      ))}
                    </div>
                  </div>
                </Col>
                <Col xs={24} md={12}>
                  <div style={{ marginBottom: 16 }}>
                    <strong>Anti-Detection Techniques:</strong>
                    <div>
                      {analysisResults.anti_detection.map((technique, index) => (
                        <Tag key={index} color="orange">{technique}</Tag>
                      ))}
                    </div>
                  </div>
                  <div>
                    <strong>Data Extraction Points:</strong>
                    <div>
                      {Object.entries(analysisResults.data_extraction).map(([key, value], index) => (
                        <Tag key={index} color="purple">{key}: {Array.isArray(value) ? value.join(', ') : value}</Tag>
                      ))}
                    </div>
                  </div>
                </Col>
              </Row>
            </div>
          </Card>

          {/* Tabs for detailed results */}
          <Card>
            <Tabs defaultActiveKey="signatures">
              <TabPane tab="Detection Signatures" key="signatures">
                <div style={{ marginBottom: 16 }}>
                  <Alert
                    message="Signatures Ready for Deployment"
                    description="Generated signatures can be deployed in YARA, Snort, SIEM systems"
                    type="success"
                    showIcon
                    action={
                      <Button size="small" icon={<DownloadOutlined />}>
                        Download All
                      </Button>
                    }
                  />
                </div>
                <Table
                  columns={signatureColumns}
                  dataSource={signatureData}
                  pagination={false}
                  size="small"
                />
              </TabPane>
              
              <TabPane tab="Attack Patterns" key="patterns">
                <div style={{ marginBottom: 16 }}>
                  <Alert
                    message="MITRE ATT&CK Mapping Complete"
                    description="All attack patterns have been mapped to MITRE framework"
                    type="info"
                    showIcon
                  />
                </div>
                <Table
                  columns={patternColumns}
                  dataSource={patternData}
                  pagination={false}
                  size="small"
                />
              </TabPane>
              
              <TabPane tab="Threat Intelligence" key="threat">
                <div style={{ marginBottom: 16 }}>
                  <h4>Generated Threat Intelligence</h4>
                  <div style={{ background: '#f5f5f5', padding: 16, borderRadius: 4 }}>
                    <pre style={{ margin: 0, fontSize: 12 }}>
{`{
  "campaign_id": "twitter_analysis_20240217",
  "threat_level": "high",
  "indicators": {
    "domains": ["twitter.com", "api.twitter.com"],
    "patterns": ["login_form", "csrf_token"],
    "techniques": ["T1056", "T1550", "T1071"]
  },
  "recommendations": [
    "Monitor for credential harvesting",
    "Deploy YARA rules for detection",
    "Update network signatures"
  ]
}`}
                    </pre>
                  </div>
                </div>
              </TabPane>
            </Tabs>
          </Card>
        </>
      )}
    </div>
  );
};

export default PhishletAnalyzer;
