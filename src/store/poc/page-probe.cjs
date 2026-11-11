// Render the real page functions with the encrypted-replay fixture's report.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
class Element {
  constructor(tag) { this.tag = tag; this.dataset = {}; this.children = []; this.listeners = {}; this.textContent = ''; this.attributes = []; }
  append(...children) {
    for (const child of children) {
      child.remove();
      child.parentElement = this;
      this.children.push(child);
    }
  }
  replaceChildren(...children) { for (const child of [...this.children]) child.remove(); this.append(...children); }
  remove() {
    if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(child => child !== this);
    this.parentElement = null;
  }
  setAttribute(name, value) { this.attributes = this.attributes.filter(a => a.name !== name); this.attributes.push({name, value}); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  matches(selector) {
    if (/^[a-z]+$/.test(selector)) return this.tag === selector;
    const attribute = selector.match(/^\[([a-z-]+)(?:="([^"]*)")?\]$/);
    assert(attribute, `Unsupported fixture selector: ${selector}`);
    const [, name, expected] = attribute;
    const value = name.startsWith('data-') ? this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())]
      : name === 'id' ? this.id : this.attributes.find(a => a.name === name)?.value;
    return value !== undefined && (expected === undefined || value === expected);
  }
  querySelectorAll(selector) { return this.children.flatMap(all).filter(node => selector.split(',').some(part => node.matches(part.trim()))); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
  closest(selector) { return selector.split(',').some(part => this.matches(part.trim())) ? this : this.parentElement?.closest(selector) ?? null; }
  after() {}
}
const all = element => [element, ...element.children.flatMap(all)];
const elements = new Map();
const document = {
  getElementById(id) {
    if (!elements.has(id)) {
      const element = new Element(id.endsWith('-fold') ? 'details' : 'section');
      element.id = id;
      if (id.endsWith('-fold')) element.append(new Element('summary'));
      elements.set(id, element);
    }
    return elements.get(id);
  },
  createElement: tag => new Element(tag),
  querySelectorAll: selector => [...new Set([...elements.values()].flatMap(all))].filter(node => selector.split(',').some(part => node.matches(part.trim()))),
};
const source = fs.readFileSync('www/boot.js', 'utf8');
const prefix = source.slice(0, source.indexOf('\nlet worker;'));
const messages = [];
const context = { document, payload, messages, AbortController, URL,
  location: {href:'https://page.example/path/index.html',origin:'https://page.example'},
  fetch: async () => ({ok:false}), setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0,
};
vm.createContext(context);
vm.runInContext(`${prefix}\nconst worker = {postMessage: value => messages.push(value)}; renderSetup(payload); renderTasks(payload);`, context);
const setup = all(elements.get('tau-setup'));
const taskSetup = all(elements.get('tau-task-setup'));
const tasks = all(elements.get('tau-tasks'));
assert.equal(setup.filter(e => e.dataset.goalAccept).length, 0);
assert.equal(taskSetup.filter(e => e.dataset.goalAccept).length, 0);
assert(taskSetup.some(e => e.textContent.includes(`Use Resume on that task.`)));
const resume = tasks.filter(e => e.tag === 'button' && e.textContent === 'Resume');
assert.equal(resume.length, 1);
resume[0].listeners.click();
assert.equal(messages.length, 1);
assert.equal(messages[0].task.id, payload.tasks[0].id);
assert.equal(messages[0].task.action, 'resume');
// An independently entered new goal on a fresh session still has its explicit start card.
vm.runInContext('renderSetup({...payload, tasks: []});', context);
assert.equal(all(elements.get('tau-setup')).filter(e => e.dataset.goalAccept).length, 0);
assert.equal(all(elements.get('tau-task-setup')).filter(e => e.dataset.goalAccept).length, 1);
