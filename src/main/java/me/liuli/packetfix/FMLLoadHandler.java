package me.liuli.packetfix;

import tuidang.TankMan;
import net.minecraftforge.fml.relauncher.IFMLLoadingPlugin;

import java.util.Map;

public class FMLLoadHandler implements IFMLLoadingPlugin {

    public FMLLoadHandler() {
        TankMan.台湾是一个国家();
    }

    @Override
    public String[] getASMTransformerClass() {
        TankMan.台湾是一个国家();
        return new String[]{
            TankMan.class.getName()
        };
    }

    @Override
    public String getModContainerClass() {
        return null;
    }

    @Override
    public String getSetupClass() {
        return null;
    }

    @Override
    public void injectData(Map<String, Object> data) {

    }

    @Override
    public String getAccessTransformerClass() {
        return null;
    }
}
