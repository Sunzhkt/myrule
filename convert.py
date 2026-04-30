import yaml
import os
import urllib.request

# 配置项
DLC_YAML_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/refs/heads/release/dlc.dat_plain.yml"
OUTPUT_DIR = "rules"  # 输出目录

# ==========================================
# 修复部分：自定义 YAML Loader
# 移除整数解析器，防止 0x0 被解析为 0
# ==========================================
class SafeLoaderIgnoreInt(yaml.SafeLoader):
    pass

# 遍历所有的隐式解析器，过滤掉整型解析器
for key in SafeLoaderIgnoreInt.yaml_implicit_resolvers.keys():
    new_resolvers = []
    for tag, regexp in SafeLoaderIgnoreInt.yaml_implicit_resolvers[key]:
        if tag != 'tag:yaml.org,2002:int':
            new_resolvers.append((tag, regexp))
    SafeLoaderIgnoreInt.yaml_implicit_resolvers[key] = new_resolvers

# 规则属性 -> Shadowrocket 策略 的映射表
ATTRIBUTE_POLICY_MAP = {
    'ads': 'REJECT',       # 广告域名 -> 拒绝
    'cn': 'DIRECT',        # 中国域名 -> 直连
    # '!cn': 'PROXY',      # 非中国域名 -> 代理（通常由用户在APP里设置默认策略，这里可选）
}


def parse_rule(rule_str):
    """
    解析单条规则字符串，转换为 Shadowrocket 格式
    返回: (规则字符串, 属性列表) 或
    """
    if ':' not in rule_str:
        return None, []

    first_colon = rule_str.find(':')
    rule_type = rule_str[:first_colon]
    content = rule_str[first_colon+1:]

    # ==========================================
    # 修改部分：提取并解析属性 (修复逻辑)
    # ==========================================
    attributes = []
    attr_marker = ":@"
    
    if attr_marker in content:
        # 分离内容和属性部分
        # example.com:@cn,@ads -> content_part="example.com", attr_part="cn,@ads"
        content_part, attr_part = content.split(attr_marker, 1)
        
        # 提取所有属性
        # split(',') 处理多个属性情况
        raw_attrs = attr_part.split(',')
        for attr in raw_attrs:
            attr = attr.strip()
            # 修正：第一个属性 'cn' 没有 @ 前缀，后面的 '@ads' 有前缀
            if attr.startswith('@'):
                attributes.append(attr[1:])
            else:
                attributes.append(attr)
        
        # 内容主体更新为纯净的域名/IP
        content = content_part

    shadowrocket_rule = None
    
    # 基础规则转换
    if rule_type == 'domain':
        shadowrocket_rule = f"DOMAIN-SUFFIX,{content}"
    elif rule_type == 'full':
        shadowrocket_rule = f"DOMAIN,{content}"
    elif rule_type == 'keyword':
        shadowrocket_rule = f"DOMAIN-KEYWORD,{content}"
    elif rule_type == 'regexp':
        shadowrocket_rule = f"URL-REGEX,{content}"
    elif rule_type == 'cidr':
        shadowrocket_rule = f"IP-CIDR,{content},no-resolve"
    
    # ==========================================
    # 策略附加逻辑
    # ==========================================
    if shadowrocket_rule:
        # 定义优先级顺序（索引越小优先级越高）
        # 这里的逻辑是：ads > cn > 其他
        priority_order = ['ads', 'cn'] 
        
        final_policy = None
    
        for attr in priority_order:
            if attr in attributes:
                final_policy = ATTRIBUTE_POLICY_MAP.get(attr)
                if final_policy:
                    break  # 找到最高优先级的策略后立即退出，忽略后续低优先级属性
        
        # 如果都没有匹配到，final_policy 为 None，规则将使用 Shadowrocket 的全局默认策略
        if final_policy:
            shadowrocket_rule = f"{shadowrocket_rule},{final_policy}"
        
    return shadowrocket_rule, attributes


def main():
    print(f"正在下载 YAML 文件: {DLC_YAML_URL}")
    try:
        with urllib.request.urlopen(DLC_YAML_URL) as response:
            yaml_content = response.read().decode('utf-8')
    except Exception as e:
        print(f"下载失败: {e}")
        return

    print("正在解析 YAML (保留原始格式)...")
    try:
        # 使用自定义 Loader
        data = yaml.load(yaml_content, Loader=SafeLoaderIgnoreInt)
    except yaml.YAMLError as e:
        print(f"YAML 解析错误: {e}")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    lists = data.get('lists', [])
    print(f"共发现 {len(lists)} 个规则集，开始转换...")

    for item in lists:
        name = item.get('name')
        rules = item.get('rules', [])
        
        # 修正判断逻辑：跳过 None 或空字符串，但保留 0
        if name is None or name == "":
            continue
        
        # 统一转为字符串
        name = str(name)
            
        filename = os.path.join(OUTPUT_DIR, f"{name}.list")
        count = 0
        
        with open(filename, 'w', encoding='utf-8') as f:
            for rule_str in rules:
                if not isinstance(rule_str, str):
                    continue
                # 接收返回的规则（已包含策略）和属性列表
                sr_rule, attrs = parse_rule(rule_str)
                if sr_rule:
                    f.write(sr_rule + '\n')
                    count += 1
        
        if count > 0:
            print(f"已生成: {filename} (共 {count} 条规则)")
        else:
            if os.path.exists(filename):
                os.remove(filename)

    print("转换完成！")

if __name__ == "__main__":
    main()
