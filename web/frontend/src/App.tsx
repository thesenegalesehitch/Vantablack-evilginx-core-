import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout, Menu, theme, Typography } from 'antd';
import { 
  DashboardOutlined, 
  BugOutlined, 
  ExperimentOutlined, 
  BarChartOutlined, 
  SettingOutlined,
  TwitterOutlined,
  SecurityScanOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';
import { styled } from 'styled-components';
import TwitterDashboard from './components/TwitterDashboard';
import Dashboard from './components/Dashboard';
import PhishletAnalyzer from './components/PhishletAnalyzer';
import MutationEngine from './components/MutationEngine';
import BehavioralAnalysis from './components/BehavioralAnalysis';
import Settings from './components/Settings';

const { Header, Sider, Content } = Layout;
const { Title } = Typography;

const StyledLayout = styled(Layout)`
  min-height: 100vh;
`;

const StyledHeader = styled(Header)`
  background: #001529;
  padding: 0 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const StyledSider = styled(Sider)`
  background: #001529;
`;

const StyledContent = styled(Content)`
  margin: 24px 16px;
  padding: 24px;
  background: #fff;
  border-radius: 8px;
  min-height: 280px;
`;

const StyledTitle = styled(Title)`
  color: #fff !important;
  margin: 0 !important;
  font-weight: 700;
`;

const App: React.FC = () => {
  const {
    token: { colorBgContainer },
  } = theme.useToken();

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
    },
    {
      key: '/twitter',
      icon: <TwitterOutlined />,
      label: 'Twitter Campaign',
    },
    {
      key: '/analyzer',
      icon: <SecurityScanOutlined />,
      label: 'Phishlet Analyzer',
    },
    {
      key: '/mutation',
      icon: <ThunderboltOutlined />,
      label: 'Mutation Engine',
    },
    {
      key: '/behavioral',
      icon: <BarChartOutlined />,
      label: 'Behavioral Analysis',
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: 'Settings',
    },
  ];

  return (
    <Router>
      <StyledLayout>
        <StyledSider>
          <div style={{ 
            height: 64, 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            borderBottom: '1px solid #303030'
          }}>
            <Title level={4} style={{ color: '#fff', margin: 0 }}>
              VANTABLACK
            </Title>
          </div>
          <Menu
            theme="dark"
            mode="inline"
            defaultSelectedKeys={['/']}
            items={menuItems}
            style={{ borderRight: 0 }}
          />
        </StyledSider>
        <Layout>
          <StyledHeader>
            <StyledTitle level={3}>Industrial Phishing Orchestrator</StyledTitle>
            <div style={{ color: '#fff' }}>
              Version 4.0.0 | Red Team Ready
            </div>
          </StyledHeader>
          <StyledContent>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/twitter" element={<TwitterDashboard />} />
              <Route path="/analyzer" element={<PhishletAnalyzer />} />
              <Route path="/mutation" element={<MutationEngine />} />
              <Route path="/behavioral" element={<BehavioralAnalysis />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </StyledContent>
        </Layout>
      </StyledLayout>
    </Router>
  );
};

export default App;
