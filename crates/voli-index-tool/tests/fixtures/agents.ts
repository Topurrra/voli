const home = homedir();
const configHome = xdgConfig ?? join(home, '.config');
const codexHome = process.env.CODEX_HOME?.trim() || join(home, '.codex');
const claudeHome = process.env.CLAUDE_CONFIG_DIR?.trim() || join(home, '.claude');

export const agents = {
  amp: {
    name: 'amp',
    globalSkillsDir: join(configHome, 'agents/skills'),
  },
  'claude-code': {
    name: 'claude-code',
    globalSkillsDir: join(claudeHome, 'skills'),
  },
  codex: {
    name: 'codex',
    globalSkillsDir: join(codexHome, 'skills'),
  },
  eve: {
    name: 'eve',
    globalSkillsDir: undefined,
  },
};
