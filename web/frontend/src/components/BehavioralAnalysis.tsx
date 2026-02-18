import React, { useState } from 'react';
import { Card, Table, Tag, Progress, Alert, Tabs, Select, DatePicker, Button } from 'antd';
import { 
  BarChartOutlined, 
  UserOutlined, 
  ClockCircleOutlined,
  GlobalOutlined,
  DownloadOutlined,
  EyeOutlined
} from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import dayjs from 'dayjs';

const { TabPane } = Tabs;
const { Option } = Select;
const { RangePicker } = DatePicker;

interface BehavioralMetrics {
  total_sessions: number;
  conversion_rate: number;
  bounce_rate: number;
  avg_session_duration: number;
  top_devices: Array<{device: string, percentage: number}>;
  top_locations: Array<{location: string, percentage: number}>;
  peak_hours: Array<{hour: number, percentage: number}>;
}

const BehavioralAnalysis: React.FC = () => {
  const [metrics, setMetrics] = useState<BehavioralMetrics>({
    total_sessions: 1250,
    conversion_rate: 8.4,
    bounce_rate: 65.2,
    avg_session_duration: 142,
    top_devices: [
      { device: 'Mobile', percentage: 58.3 },
      { device: 'Desktop', percentage: 31.7 },
      { device: 'Tablet', percentage: 10.0 }
    ],
    top_locations: [
      { location: 'United States', percentage: 35.2 },
      { location: 'United Kingdom', percentage: 18.7 },
      { location: 'Canada', percentage: 12.4 },
      { location: 'Germany', percentage: 8.9 },
      { location: 'France', percentage: 6.8 }
    ],
    peak_hours: [
      { hour: 9, percentage: 12.3 },
      { hour: 14, percentage: 18.7 },
      { hour: 18, percentage: 22.1 },
      { hour: 21, percentage: 15.4 }
    ]
  });

  const hourlyData = [
    { hour: '00', sessions: 45, conversions: 3 },
    { hour: '03', sessions: 23, conversions: 1 },
    { hour: '06', sessions: 67, conversions: 4 },
    { hour: '09', sessions: 156, conversions: 15 },
    { hour: '12', sessions: 189, conversions: 18 },
    { hour: '15', sessions: 234, conversions: 22 },
    { hour: '18', sessions: 278, conversions: 28 },
    { hour: '21', sessions: 198, conversions: 17 }
  ];

  const deviceData = metrics.top_devices.map(d => ({
    name: d.device,
    value: d.percentage
  }));

  const locationData = metrics.top_locations.map(l => ({
    name: l.location,
    value: l.percentage
  }));

  const segmentColumns = [
    { title: 'Segment', dataIndex: 'segment', key: 'segment' },
    { title: 'Users', dataIndex: 'users', key: 'users' },
    { title: 'Conversion Rate', dataIndex: 'conversionRate', key: 'conversionRate' },
    { title: 'Value Score', dataIndex: 'valueScore', key: 'valueScore' },
    { title: 'Priority', dataIndex: 'priority', key: 'priority' }
  ];

  const segmentData = [
    { key: '1', segment: 'High Mobile Users', users: 728, conversionRate: '12.4%', valueScore: 0.85, priority: 'High' },
    { key: '2', segment: 'Evening Engagers', users: 445, conversionRate: '9.8%', valueScore: 0.72, priority: 'Medium' },
    { key: '3', segment: 'Desktop Professionals', users: 397, conversionRate: '15.2%', valueScore: 0.91, priority: 'High' },
    { key: '4', segment: 'Weekend Visitors', users: 234, conversionRate: '6.3%', valueScore: 0.45, priority: 'Low' }
  ];

  const recommendationColumns = [
    { title: 'Category', dataIndex: 'category', key: 'category' },
    { title: 'Recommendation', dataIndex: 'recommendation', key: 'recommendation' },
    { title: 'Expected Lift', dataIndex: 'expectedLift', key: 'expectedLift' },
    { title: 'Priority', dataIndex: 'priority', key: 'priority' }
  ];

  const recommendationData = [
    { key: '1', category: 'Design', recommendation: 'Optimize mobile layout', expectedLift: '+15%', priority: 'High' },
    { key: '2', category: 'Timing', recommendation: 'Schedule campaigns at 18:00', expectedLift: '+22%', priority: 'High' },
    { key: '3', category: 'Content', recommendation: 'Simplify form fields', expectedLift: '+18%', priority: 'Medium' },
    { key: '4', category: 'Targeting', recommendation: 'Focus on US users', expectedLift: '+8%', priority: 'Low' }
  ];

  const COLORS = ['#1890ff', '#52c41a', '#faad14', '#ff4d4f'];

  const getPerformanceColor = (rate: number) => {
    if (rate > 10) return '#52c41a';
    if (rate > 5) return '#faad14';
    return '#ff4d4f';
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'High': return 'red';
      case 'Medium': return 'orange';
      case 'Low': return 'green';
      default: return 'default';
    }
  };

  return (
    <div className="behavioral-analysis">
      <div style={{ marginBottom: 24 }}>
        <h2><BarChartOutlined /> Behavioral Analysis</h2>
        <p>User behavior insights and campaign optimization</p>
      </div>

      {/* Key Metrics */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <Card size="small">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, color: '#1890ff' }}>{metrics.total_sessions.toLocaleString()}</div>
              <div style={{ color: '#666' }}>Total Sessions</div>
            </div>
          </Card>
          <Card size="small">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, color: getPerformanceColor(metrics.conversion_rate) }}>
                {metrics.conversion_rate}%
              </div>
              <div style={{ color: '#666' }}>Conversion Rate</div>
            </div>
          </Card>
          <Card size="small">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, color: getPerformanceColor(100 - metrics.bounce_rate) }}>
                {metrics.bounce_rate}%
              </div>
              <div style={{ color: '#666' }}>Bounce Rate</div>
            </div>
          </Card>
          <Card size="small">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, color: '#722ed1' }}>
                {Math.floor(metrics.avg_session_duration / 60)}:{(metrics.avg_session_duration % 60).toString().padStart(2, '0')}
              </div>
              <div style={{ color: '#666' }}>Avg Duration</div>
            </div>
          </Card>
        </div>
      </div>

      {/* Charts */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 16 }}>
          <Card title="Hourly Activity" size="small">
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={hourlyData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="sessions" stroke="#1890ff" name="Sessions" />
                <Line type="monotone" dataKey="conversions" stroke="#52c41a" name="Conversions" />
              </LineChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Device Distribution" size="small">
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={deviceData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {deviceData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </div>
      </div>

      {/* Detailed Analysis */}
      <Card>
        <Tabs defaultActiveKey="segments">
          <TabPane tab="User Segments" key="segments">
            <div style={{ marginBottom: 16 }}>
              <Alert
                message="High-Value Segments Identified"
                description="3 segments showing above-average conversion rates"
                type="success"
                showIcon
              />
            </div>
            <Table
              columns={segmentColumns}
              dataSource={segmentData}
              pagination={false}
              size="small"
            />
          </TabPane>

          <TabPane tab="Geographic Analysis" key="geographic">
            <div style={{ marginBottom: 16 }}>
              <h4>Top Locations by Engagement</h4>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={locationData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {locationData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            
            <div>
              <h4>Geographic Insights</h4>
              <ul>
                <li>North America accounts for 53.9% of all sessions</li>
                <li>European users show 23% higher conversion rates</li>
                <li>Peak activity times vary by region</li>
                <li>Mobile usage highest in US (67%)</li>
              </ul>
            </div>
          </TabPane>

          <TabPane tab="Optimization Recommendations" key="recommendations">
            <div style={{ marginBottom: 16 }}>
              <Alert
                message="4 Optimization Opportunities"
                description="Based on behavioral analysis and performance metrics"
                type="info"
                showIcon
                action={
                  <Button size="small" icon={<DownloadOutlined />}>
                    Export Report
                  </Button>
                }
              />
            </div>
            
            <Table
              columns={recommendationColumns}
              dataSource={recommendationData}
              pagination={false}
              size="small"
            />
            
            <div style={{ marginTop: 24 }}>
              <h4>Implementation Priority</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div>
                  <Tag color="red">High Priority</Tag>
                  <span style={{ marginLeft: 8 }}>Mobile optimization and peak timing</span>
                </div>
                <div>
                  <Tag color="orange">Medium Priority</Tag>
                  <span style={{ marginLeft: 8 }}>Form simplification and content improvements</span>
                </div>
                <div>
                  <Tag color="green">Low Priority</Tag>
                  <span style={{ marginLeft: 8 }}>Geographic targeting adjustments</span>
                </div>
              </div>
            </div>
          </TabPane>

          <TabPane tab="Funnel Analysis" key="funnel">
            <div style={{ marginBottom: 24 }}>
              <h4>Conversion Funnel</h4>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                {[
                  { stage: 'Page Views', count: 1250, rate: 100 },
                  { stage: 'Form Interactions', count: 890, rate: 71.2 },
                  { stage: 'Submission Attempts', count: 234, rate: 18.7 },
                  { stage: 'Successful Conversions', count: 105, rate: 8.4 }
                ].map((step, index) => (
                  <div key={index} style={{ textAlign: 'center', flex: 1 }}>
                    <div style={{ fontSize: 24, fontWeight: 'bold', color: '#1890ff' }}>
                      {step.count}
                    </div>
                    <div style={{ fontSize: 12, color: '#666' }}>{step.stage}</div>
                    <div style={{ fontSize: 14, color: '#52c41a' }}>{step.rate}%</div>
                  </div>
                ))}
              </div>
              
              <div>
                <Progress 
                  percent={8.4} 
                  strokeColor="#52c41a"
                  format={() => 'Overall Conversion: 8.4%'}
                />
              </div>
            </div>
            
            <div>
              <h4>Drop-off Analysis</h4>
              <ul>
                <li>Largest drop-off: Page Views to Form Interactions (28.8%)</li>
                <li>Second drop-off: Form to Submission (52.6%)</li>
                <li>Final drop-off: Submission to Conversion (55.1%)</li>
                <li>Recommendation: Focus on form optimization and trust signals</li>
              </ul>
            </div>
          </TabPane>
        </Tabs>
      </Card>
    </div>
  );
};

export default BehavioralAnalysis;
