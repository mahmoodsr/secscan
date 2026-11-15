import {defineConfig} from '@playwright/test';
export default defineConfig({
  testDir:'./test',timeout:60_000,workers:1,
  use:{actionTimeout:8000,trace:'retain-on-failure',viewport:{width:1440,height:1050},...(process.env.SECSCAN_BROWSER_CHANNEL?{channel:process.env.SECSCAN_BROWSER_CHANNEL}:{})},
});
