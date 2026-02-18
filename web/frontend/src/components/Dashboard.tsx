import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Progress, Alert, Button, Table, Tag } from 'antd';
import { 
  BugOutlined, 
  ThunderboltOutlined, 
  BarChartOutlined, 
  SecurityScanOutlined,
  TwitterOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import axios from 'axios';

interface DashboardMetrics {
  total_phishlets: number;
  active_campaigns: number;
  success_rate: number;
  detection_rate: number;
  mutations_generated: number;
  signatures_created: number;
}

const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 60000); // Update every minute
    return () => clearInterval(interval);
  }, []);

  const fetchMetrics = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/dashboard/metrics');
      setMetrics(response.data);
    } catch (error) {
      console.error('Error fetching dashboard metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  const performanceData = [
    { name: 'Mon', success: 4.2, detection: 1.1 },
    { name: 'Tue', success: 5.8, detection: 0.9 },
    { name: 'Wed', success: 7.1, detection: 1.3 },
    { name: 'Thu', success: 6.4, detection: 0.8 },
    { name: 'Fri', success: 8.2, detection: 1.5 },
    { name: 'Sat', success: 9.1, detection: 1.2 },
    { name: 'Sun', success: 7.8, detection: 0.7 }
  ];

  const recentActivity = [
    { key: '1', action: 'Twitter phishlet analyzed', status: 'completed', time: '2 mins ago' },
    { key: '2', action: 'Generated 5 variants', status: 'completed', time: '15 mins ago' },
    { key: '3', action: 'MFA bypass optimization', status: 'in_progress', time: '1 hour ago' },
    { key: '4', action: 'Domain rotation', status: 'completed', time: '2 hours ago' },
    { key: '5', action: 'Signature generation', status: 'completed', time: '3 hours ago' }
  ];

  const activityColumns = [
    { title: 'Action', dataIndex: 'action', key: 'action' },
    { 
      title: 'Status', 
      dataIndex: 'status', 
      key: 'status',
      render: (status: string) => (
        <Tag color={status === 'completed' ? 'green' : status === 'in_progress' ? 'blue' : 'default'}>
          {status.replace('_', ' ').toUpperCase()}
        </Tag>
      )
    },
    { title: 'Time', dataIndex: 'time', key: 'time' }
  ];

  return (
    <div className="dashboard">
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <Row justify="space-between" align="middle">
          <Col>
            <h2>VANTABLACK Dashboard</h2>
            <p>Real-time overview of your phishing campaigns</p>
          </Col>
          <Col>
            <Button 
              icon={<ReloadOutlined />} 
              onClick={fetchMetrics}
              loading={loading}
            >
              Refresh
            </Button>
          </Col>
        </Row>
      </div>

      {/* Key Metrics */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Total Phishlets"
              value={metrics?.total_phishlets || 0}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Active Campaigns"
              value={metrics?.active_campaigns || 0}
              prefix={<ThunderboltOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Success Rate"
              value={metrics?.success_rate || 0}
              precision={1}
              suffix="%"
              prefix={<BarChartOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Detection Rate"
              value={metrics?.detection_rate || 0}
              precision={1}
              suffix="%"
              prefix={<SecurityScanOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* Performance Chart */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={16}>
          <Card title="Weekly Performance" size="small">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={performanceData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="success" stroke="#52c41a" name="Success Rate %" />
                <Line type="monotone" dataKey="detection" stroke="#ff4d4f" name="Detection Rate %" />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        
        <Col xs={24} lg={8}>
          <Card title="System Health" size="small">
            <div style={{ marginBottom: 16 }}>
              <div style={{ marginBottom: 8 }}>
                <span>CPU Usage</span>
                <Progress percent={35} strokeColor="#52c41a" />
              </div>
              <div style={{ marginBottom: 8 }}>
                <span>Memory Usage</span>
                <Progress percent={68} strokeColor="#1890ff" />
              </div>
              <div style={{ marginBottom: 8 }}>
                <span>Storage</span>
                <Progress percent={42} strokeColor="#722ed1" />
              </div>
              <div>
                <span>Network</span>
                <Progress percent={15} strokeColor="#faad14" />
              </div>
            </div>
          </Card>
        </Col>
      </Row>

      {/* Recent Activity & Quick Actions */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={16}>
          <Card title="Recent Activity" size="small">
            <Table
              columns={activityColumns}
              dataSource={recentActivity}
              pagination={false}
              size="small"
            />
          </Card>
        </Col>
        
        <Col xs={24} lg={8}>
          <Card title="Quick Actions" size="small">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <Button type="primary" icon={<TwitterOutlined />} block>
                Analyze Twitter Phishlet
              </Button>
              <Button icon={<BugOutlined />} block>
                Generate Variants
              </Button>
              <Button icon={<ThunderboltOutlined />} block>
                Start Campaign
              </Button>
              <Button icon={<SecurityScanOutlined />} block>
                View Signatures
              </Button>
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
