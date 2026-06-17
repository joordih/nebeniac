package dev.neuralabs.plugin;

import org.bukkit.plugin.java.JavaPlugin;

public class DummyPlugin extends JavaPlugin {
  @Override
  public void onEnable() {
    getLogger().info("DummyPlugin started - SecurePluginLoader will handle loading the real plugin");
  }

  @Override
  public void onDisable() {
    getLogger().info("DummyPlugin disabled");
  }
}
