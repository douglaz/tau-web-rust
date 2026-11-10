// Render the real page functions with the encrypted-replay fixture's report.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
class Element {
  constructor(tag) { this.tag = tag; this.dataset = {}; this.children = []; this.listeners = {}; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute() {}
  addEventListener(name, fn) { this.listeners[name] = fn; }
  after() {}
}
const elements = new Map();
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element('section'));
    return elements.get(id);
  },
  createElement: tag => new Element(tag),
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
const all = element => [element, ...element.children.flatMap(all)];
const setup = all(elements.get('tau-setup'));
const tasks = all(elements.get('tau-tasks'));
assert.equal(setup.filter(e => e.dataset.goalAccept).length, 0);
assert(setup.some(e => e.textContent.includes(`Use Resume on that task.`)));
const resume = tasks.filter(e => e.tag === 'button' && e.textContent === 'Resume');
assert.equal(resume.length, 1);
resume[0].listeners.click();
assert.equal(messages.length, 1);
assert.equal(messages[0].task.id, payload.tasks[0].id);
assert.equal(messages[0].task.action, 'resume');
// An independently entered new goal on a fresh session still has its explicit start card.
vm.runInContext('renderSetup({...payload, tasks: []});', context);
assert.equal(all(elements.get('tau-setup')).filter(e => e.dataset.goalAccept).length, 1);
