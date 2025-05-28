import React, { useState, useEffect, useMemo } from 'react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, Users, Server, Zap, Shield, TrendingUp, AlertTriangle, Clock, Globe, Cpu, HardDrive, Database } from 'lucide-react';

// Main Dashboard Component
export default function VortexDashboard() {
  const [timeRange, setTimeRange] = useState('24h');
  const [systemMetrics, setSystemMetrics] = useState({
    activeUsers: 1250,
    activeConnections: 3847,
    totalTraffic: 2.47,
    bandwidthUsage: 847.3,
    cpuUsage: 45.2,
    memoryUsage: 62.8,
    diskUsage: 34.5
  });

  const [trafficData, setTrafficData] = useState([]);
  const [protocolDistribution, setProtocolDistribution] = useState([]);
  const [topUsers, setTopUsers] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [predictions, setPredictions] = useState([]);

  // Simulate real-time data updates
  useEffect(() => {
    // Generate sample traffic data
    const generateTrafficData = () => {
      const data = [];
      const now = Date.now();
      for (let i = 23; i >= 0; i--) {
        data.push({
          time: new Date(now - i * 3600000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
          upload: Math.floor(Math.random() * 500) + 200,
          download: Math.floor(Math.random() * 800) + 400,
          total: 0
        });
        data[data.length - 1].total = data[data.length - 1].upload + data[data.length - 1].download;
      }
      return data;
    };

    // Generate protocol distribution
    const generateProtocolData = () => [
      { name: 'VLESS', value: 42, color: '#8B5CF6' },
      { name: 'VMess', value: 28, color: '#3B82F6' },
      { name: 'Trojan', value: 18, color: '#10B981' },
      { name: 'Shadowsocks', value: 8, color: '#F59E0B' },
      { name: 'WireGuard', value: 4, color: '#EF4444' }
    ];

    // Generate top users
    const generateTopUsers = () => [
      { name: 'user_1a2b3c', traffic: 45.2, trend: 'up' },
      { name: 'user_4d5e6f', traffic: 38.7, trend: 'up' },
      { name: 'user_7g8h9i', traffic: 32.1, trend: 'down' },
      { name: 'user_0j1k2l', traffic: 28.9, trend: 'stable' },
      { name: 'user_3m4n5o', traffic: 24.3, trend: 'up' }
    ];

    // Generate anomalies
    const generateAnomalies = () => [
      { id: 1, type: 'spike', severity: 'medium', client: 'user_1a2b3c', time: '2 hours ago', value: '+250%' },
      { id: 2, type: 'drop', severity: 'low', client: 'user_7g8h9i', time: '5 hours ago', value: '-80%' },
      { id: 3, type: 'pattern', severity: 'high', client: 'user_9z8y7x', time: '1 hour ago', value: 'Unusual activity' }
    ];

    // Generate predictions
    const generatePredictions = () => {
      const data = [];
      for (let i = 0; i < 7; i++) {
        const date = new Date();
        date.setDate(date.getDate() + i);
        data.push({
          date: date.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }),
          predicted: Math.floor(Math.random() * 200) + 800,
          upper: Math.floor(Math.random() * 100) + 900,
          lower: Math.floor(Math.random() * 100) + 700
        });
      }
      return data;
    };

    setTrafficData(generateTrafficData());
    setProtocolDistribution(generateProtocolData());
    setTopUsers(generateTopUsers());
    setAnomalies(generateAnomalies());
    setPredictions(generatePredictions());

    // Simulate real-time updates
    const interval = setInterval(() => {
      setSystemMetrics(prev => ({
        ...prev,
        activeConnections: prev.activeConnections + Math.floor(Math.random() * 10) - 5,
        bandwidthUsage: prev.bandwidthUsage + (Math.random() * 20) - 10,
        cpuUsage: Math.min(100, Math.max(0, prev.cpuUsage + (Math.random() * 4) - 2)),
        memoryUsage: Math.min(100, Math.max(0, prev.memoryUsage + (Math.random() * 2) - 1))
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, [timeRange]);

  // Metric Card Component
  const MetricCard = ({ icon: Icon, title, value, unit, trend, color }) => (
    <div className="bg-white rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold mt-2">
            {value}
            <span className="text-sm font-normal text-gray-500 ml-1">{unit}</span>
          </p>
          {trend && (
            <p className={`text-sm mt-2 ${trend > 0 ? 'text-green-500' : 'text-red-500'}`}>
              {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
            </p>
          )}
        </div>
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  );

  // Progress Bar Component
  const ProgressBar = ({ label, value, color }) => (
    <div className="mb-4">
      <div className="flex justify-between mb-1">
        <span className="text-sm font-medium text-gray-700">{label}</span>
        <span className="text-sm text-gray-500">{value}%</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div 
          className={`h-2 rounded-full ${color}`} 
          style={{ width: `${value}%` }}
        />
      </div>
    </div>
  );

  // Anomaly Badge Component
  const AnomalyBadge = ({ severity }) => {
    const colors = {
      low: 'bg-yellow-100 text-yellow-800',
      medium: 'bg-orange-100 text-orange-800',
      high: 'bg-red-100 text-red-800',
      critical: 'bg-purple-100 text-purple-800'
    };
    
    return (
      <span className={`px-2 py-1 text-xs rounded-full ${colors[severity]}`}>
        {severity.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">VortexPanel Dashboard</h1>
        <p className="text-gray-600 mt-2">Real-time monitoring and analytics</p>
      </div>

      {/* Time Range Selector */}
      <div className="mb-6 flex space-x-2">
        {['1h', '6h', '24h', '7d', '30d'].map((range) => (
          <button
            key={range}
            onClick={() => setTimeRange(range)}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              timeRange === range 
                ? 'bg-indigo-600 text-white' 
                : 'bg-white text-gray-700 hover:bg-gray-100'
            }`}
          >
            {range}
          </button>
        ))}
      </div>

      {/* System Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard 
          icon={Users} 
          title="Active Users" 
          value={systemMetrics.activeUsers.toLocaleString()} 
          unit="users"
          trend={5.2}
          color="bg-indigo-500"
        />
        <MetricCard 
          icon={Activity} 
          title="Active Connections" 
          value={systemMetrics.activeConnections.toLocaleString()} 
          unit="connections"
          trend={-2.3}
          color="bg-blue-500"
        />
        <MetricCard 
          icon={Server} 
          title="Total Traffic" 
          value={systemMetrics.totalTraffic} 
          unit="TB"
          trend={12.5}
          color="bg-green-500"
        />
        <MetricCard 
          icon={Zap} 
          title="Bandwidth Usage" 
          value={systemMetrics.bandwidthUsage.toFixed(1)} 
          unit="Mbps"
          color="bg-yellow-500"
        />
      </div>

      {/* Traffic Chart */}
      <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
        <h2 className="text-xl font-bold mb-4">Traffic Overview</h2>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={trafficData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Area 
              type="monotone" 
              dataKey="download" 
              stackId="1" 
              stroke="#3B82F6" 
              fill="#3B82F6" 
              fillOpacity={0.6}
            />
            <Area 
              type="monotone" 
              dataKey="upload" 
              stackId="1" 
              stroke="#10B981" 
              fill="#10B981" 
              fillOpacity={0.6}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        {/* Protocol Distribution */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4">Protocol Distribution</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={protocolDistribution}
                cx="50%"
                cy="50%"
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}%`}
              >
                {protocolDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* System Resources */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4">System Resources</h2>
          <ProgressBar 
            label="CPU Usage" 
            value={systemMetrics.cpuUsage.toFixed(1)} 
            color="bg-blue-500"
          />
          <ProgressBar 
            label="Memory Usage" 
            value={systemMetrics.memoryUsage.toFixed(1)} 
            color="bg-green-500"
          />
          <ProgressBar 
            label="Disk Usage" 
            value={systemMetrics.diskUsage.toFixed(1)} 
            color="bg-yellow-500"
          />
          <div className="mt-4 flex items-center space-x-4 text-sm text-gray-600">
            <div className="flex items-center">
              <Cpu className="w-4 h-4 mr-1" />
              <span>8 cores</span>
            </div>
            <div className="flex items-center">
              <HardDrive className="w-4 h-4 mr-1" />
              <span>16 GB RAM</span>
            </div>
            <div className="flex items-center">
              <Database className="w-4 h-4 mr-1" />
              <span>500 GB SSD</span>
            </div>
          </div>
        </div>

        {/* Top Users */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4">Top Users by Traffic</h2>
          <div className="space-y-3">
            {topUsers.map((user, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center text-sm font-medium">
                    {index + 1}
                  </div>
                  <span className="ml-3 font-medium">{user.name}</span>
                </div>
                <div className="flex items-center">
                  <span className="text-sm text-gray-600">{user.traffic} GB</span>
                  {user.trend === 'up' && <TrendingUp className="w-4 h-4 text-green-500 ml-2" />}
                  {user.trend === 'down' && <TrendingUp className="w-4 h-4 text-red-500 ml-2 rotate-180" />}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Anomalies and Predictions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Anomalies */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold">Anomalies Detected</h2>
            <AlertTriangle className="w-5 h-5 text-orange-500" />
          </div>
          <div className="space-y-3">
            {anomalies.map((anomaly) => (
              <div key={anomaly.id} className="border rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium">{anomaly.client}</span>
                  <AnomalyBadge severity={anomaly.severity} />
                </div>
                <div className="flex items-center justify-between text-sm text-gray-600">
                  <span>{anomaly.value}</span>
                  <span className="flex items-center">
                    <Clock className="w-3 h-3 mr-1" />
                    {anomaly.time}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Traffic Predictions */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4">Traffic Predictions</h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={predictions}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="predicted" 
                stroke="#8B5CF6" 
                strokeWidth={2}
                dot={{ fill: '#8B5CF6' }}
              />
              <Line 
                type="monotone" 
                dataKey="upper" 
                stroke="#E5E7EB" 
                strokeDasharray="5 5"
                dot={false}
              />
              <Line 
                type="monotone" 
                dataKey="lower" 
                stroke="#E5E7EB" 
                strokeDasharray="5 5"
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}