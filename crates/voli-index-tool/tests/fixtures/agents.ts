const home = homedir();
const configHome = xdgConfig ?? join(home, '.config');
const codexHome = process.env.CODEX_HOME?.trim() || join(home, '.codex');
const claudeHome = process.env.CLAUDE_CONFIG_DIR?.trim() || join(home, '.claude');

export const agents = {
  amp: {
    name: 'amp',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(configHome, 'agents/skills'),
  },
  'claude-code': {
    name: 'claude-code',
    skillsDir: '.claude/skills',
    globalSkillsDir: join(claudeHome, 'skills'),
  },
  codex: {
    name: 'codex',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(codexHome, 'skills'),
  },
  eve: {
    name: 'eve',
    skillsDir: 'skills',
    globalSkillsDir: undefined,
  },
  zed: {
    name: 'zed',
    skillsDir: '.agents/skills',
    globalSkillsDir: join(home, '.agents/skills'),
    detectInstalled: async () => {
      return existsSync(join(configHome, 'zed'));
    },
  },
};
