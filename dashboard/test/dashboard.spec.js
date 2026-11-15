import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../..',import.meta.url));
const screenshots=process.env.SECSCAN_SCREENSHOTS;

test('automated · scan, filter, compare, export and accessible themes',async({page})=>{
  const folder=await mkdtemp(join(tmpdir(),'secscan-browser-'));
  const project=join(folder,'sample-app');
  await mkdir(project);
  const python=process.env.SECSCAN_TEST_PYTHON|| (process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python');
  const server=spawn(resolve(root,python),[join(root,'dashboard/test/harness.py'),join(folder,'data')],{
    cwd:root,env:{...process.env,PYTHONPATH:root},stdio:['ignore','pipe','inherit']});
  let opened;
  try{
    opened=await Promise.race([once(server.stdout,'data').then(([chunk])=>chunk.toString().trim()),
      once(server,'exit').then(([code])=>{throw Error('Dashboard exited '+code);})]);
    await page.goto(opened);
    await expect(page.getByRole('heading',{level:1})).toHaveText('Security Overview');
    const gauge=page.locator('.gauge-panel');
    await expect(gauge).toContainText('Run a scan to view its report.');
    await expect(gauge.getByRole('img',{name:/Tools passed:/})).toHaveCount(0);
    const nav=page.getByRole('navigation');
    const select=async name=>{await nav.getByRole('button',{name,exact:true}).click();};
    const shot=async name=>{if(screenshots){await page.evaluate(()=>document.fonts.ready);await page.screenshot({path:join(screenshots,name+'.png'),fullPage:true});}};
    const accessibility=async ()=>expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze()).violations).toEqual([]);
    const launch=async mode=>{
      await writeFile(join(project,'scenario'),mode);
      await select('Scan run');
      await page.getByLabel('Project folder').fill(project);
      const [response]=await Promise.all([
        page.waitForResponse(r=>r.url().endsWith('/api/runs')&&r.request().method()==='POST'),
        page.getByRole('button',{name:'Start scan'}).click(),
      ]);
      expect(response.ok()).toBeTruthy();
      const {id}=await response.json();
      await expect.poll(async()=>page.evaluate(async id=>{
        const state=await fetch('/api/state').then(r=>r.json());
        return state.history.some(row=>row.id===id);
      },id)).toBeTruthy();
    };
    await launch('fixed');
    await expect(page.getByRole('button',{name:'View report',exact:true})).toBeVisible();
    await select('Overview');
    await expect(gauge.getByRole('img',{name:'Tools passed: 4 / 4'})).toBeVisible();
    await launch('findings');
    await expect(page.getByRole('button',{name:'View report',exact:true})).toBeVisible();
    await shot('03-scan-run');
    await page.getByRole('button',{name:'View report',exact:true}).click();
    await expect(page.getByRole('heading',{name:'sample-app',exact:true})).toBeVisible();
    await shot('04-results');
    const download=page.waitForEvent('download');
    await page.getByRole('link',{name:'JSON',exact:true}).click();
    expect((await download).suggestedFilename()).toBe('summary.json');
    await select('Overview');
    await expect(page.getByRole('heading',{name:'Must fix'})).toBeVisible();
    await expect(gauge.getByRole('img',{name:'Tools passed: 1 / 4'})).toBeVisible();
    await expect(gauge.getByRole('listitem').filter({hasText:'SonarQube'})).toContainText('Pass');
    await shot('01-overview');
    await select('History');
    await page.getByRole('row').filter({hasText:'Pass'}).getByRole('button',{name:'View report'}).click();
    await expect(page.locator('main section').filter({has:page.getByRole('heading',{name:'sample-app',exact:true})})).toContainText('Pass');
    await select('Overview');
    await expect(gauge.getByRole('img',{name:'Tools passed: 1 / 4'})).toBeVisible();
    await accessibility();
    await page.getByRole('button',{name:'Toggle light or dark theme'}).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme','light');
    await accessibility();
    await page.getByRole('button',{name:'Toggle light or dark theme'}).click();
    await select('Findings');
    await page.getByRole('combobox',{name:'Category',exact:true}).selectOption('secret');
    await page.getByRole('button',{name:'github-pat',exact:true}).click();
    await expect(page.getByRole('dialog')).toContainText('app.js:1');
    await expect(page.getByRole('dialog')).not.toContainText('Possible credential exposure');
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).not.toBeVisible();
    await page.getByRole('combobox',{name:'Category',exact:true}).selectOption('');
    await shot('05-findings');
    await select('Setup');
    await expect(page.getByText('Install command').first()).toBeVisible();
    await shot('02-setup');
    await select('Settings');
    await expect(page.getByText('Read-only policy')).toBeVisible();
    await shot('07-settings');
    await launch('fixed');
    await expect(page.getByRole('button',{name:'View report',exact:true})).toBeVisible();
    await select('History');
    await page.getByRole('button',{name:'Compare scans',exact:true}).click();
    await expect(page.getByRole('heading',{name:/Fixed · [1-9]/})).toBeVisible();
    await shot('06-history');
    await page.emulateMedia({reducedMotion:'reduce',reducedTransparency:'reduce'});
    const osTransparency=await page.evaluate(()=>matchMedia('(prefers-reduced-transparency: reduce)').matches);
    if(!osTransparency){
      await select('Settings');
      await page.getByRole('checkbox',{name:'Use solid surfaces'}).check();
      await select('History');
    }
    await expect(page.locator('.panel').first()).toHaveCSS('backdrop-filter','none');
    await page.setViewportSize({width:390,height:844});
    await expect(page.getByRole('heading',{level:1})).toBeVisible();
    const width=await page.evaluate(()=>document.documentElement.scrollWidth);
    expect(width).toBeLessThanOrEqual(390);
  }finally{
    if(server.exitCode===null){const done=once(server,'exit');server.kill();await done;}
    await rm(folder,{recursive:true,force:true});
  }
});
