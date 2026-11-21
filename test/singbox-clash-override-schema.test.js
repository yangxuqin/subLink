import { describe, it, expect } from 'vitest';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { SING_BOX_CONFIG, SING_BOX_CONFIG_V1_11 } from '../src/config/singboxConfig.js';

const clashYaml = `
port: 7890
socks-port: 7891
allow-lan: false
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090
unified-delay: true
hosts:
  time.android.com: 17.253.84.125
proxy-providers:
  remote:
    type: http
    url: https://example.com/provider
experimental:
  quic-go-disable-gso: true
dns:
  enable: true
  use-hosts: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - 223.5.5.5
  nameserver-policy:
    "+.example.com": "223.5.5.5"
proxies:
  - name: test-node
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`;

const singboxInput = JSON.stringify({
    outbounds: [{
        type: 'vless',
        tag: 'test-node',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000000'
    }],
    log: { level: 'debug' },
    experimental: { cache_file: { enabled: false } }
});

function build(input, { version = '1.14', baseConfig = SING_BOX_CONFIG } = {}) {
    return new SingboxConfigBuilder(
        input, [], [], baseConfig, 'en-US', null,
        false, false, null, null, version, false
    ).build();
}

describe('sing-box override schema sanitization', () => {
    it('drops Clash-only top-level and DNS options from a Clash subscription', async () => {
        const config = await build(clashYaml);

        for (const key of [
            'port', 'socks-port', 'allow-lan', 'mode', 'log-level',
            'external-controller', 'unified-delay', 'hosts', 'proxy-providers'
        ]) {
            expect(config).not.toHaveProperty(key);
        }

        expect(Object.keys(config.dns).sort()).toEqual(['final', 'rules', 'servers']);
        expect(config.dns.servers.map(server => server.tag)).toContain('dns_resolver');
        expect(config.route.default_domain_resolver).toBe('dns_resolver');
        expect(config.experimental).not.toHaveProperty('quic-go-disable-gso');
        expect(config.inbounds).toHaveLength(2);
    });

    it('keeps valid sing-box overrides from a sing-box subscription', async () => {
        const config = await build(singboxInput);

        expect(config.log).toEqual({ level: 'debug' });
        expect(config.experimental.cache_file).toEqual({ enabled: false });
        expect(config.outbounds.some(outbound => outbound.tag === 'test-node')).toBe(true);
    });

    it('drops legacy dns.fakeip from sing-box overrides on 1.14', async () => {
        const input = JSON.stringify({
            ...JSON.parse(singboxInput),
            dns: { fakeip: { enabled: true, inet4_range: '198.18.0.0/15' } }
        });
        const config = await build(input, { version: '1.14' });

        expect(config.dns).not.toHaveProperty('fakeip');
    });

    it('keeps legacy dns.fakeip for 1.11 templates', async () => {
        const config = await build(clashYaml, {
            version: '1.11',
            baseConfig: SING_BOX_CONFIG_V1_11
        });

        expect(config.dns.fakeip).toEqual({
            enabled: true,
            inet4_range: '198.18.0.0/15',
            inet6_range: 'fc00::/18'
        });
    });

    it('keeps Clash proxy-groups available for the group merge', async () => {
        const input = `${clashYaml}
proxy-groups:
  - name: Manual
    type: select
    proxies:
      - test-node
`;
        const config = await build(input);

        expect(config).not.toHaveProperty('proxy-groups');
        const group = config.outbounds.find(outbound => outbound.tag === 'Manual');
        expect(group).toMatchObject({ type: 'selector', outbounds: ['test-node'] });
    });
});
