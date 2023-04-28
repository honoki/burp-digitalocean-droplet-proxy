package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JDialog;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import com.myjeeva.digitalocean.*;
import com.myjeeva.digitalocean.impl.DigitalOceanClient;
import com.myjeeva.digitalocean.pojo.*;
import com.myjeeva.digitalocean.exception.*;

public class BurpExtender extends JDialog implements IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab  {

    private IBurpExtenderCallbacks callbacks;
	protected PrintWriter stdout;
    protected String api_key;
    private String ip;
    private DigitalOcean apiClient;

    // gui elements
	public DigitalOceanProxyTab myPanel;

    // keep a copy of our proxy droplet
    Droplet droplet;
    // the script to run on the droplet when it is created
    private String droplet_init_script = "#!/bin/bash\ndocker run -d --name socks5 -p 1080:1080 -e PROXY_USER=burp -e PROXY_PASSWORD=changeme serjs/go-socks5-proxy";
    // the socks password
    private CharSequence password;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("DigitalOcean Droplet Proxy");
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;

		// unload resources when this extension is removed;
        stdout.println("Registering extension state listener.");
		callbacks.registerExtensionStateListener(this);

        // load existing settings
        stdout.println("Loading existing settings.");
        this.api_key = callbacks.loadExtensionSetting("digitalocean-api-key");

        // create the tab
        stdout.println("Creating DigitalOcean Droplet Proxy tab.");
        myPanel = new DigitalOceanProxyTab(this);
        callbacks.addSuiteTab(this);

        // register the right-click menu:
		callbacks.registerContextMenuFactory(this);

        stdout.println("DigitalOcean Droplet Proxy extension initialized.");
    
    }

    // use the DigitalOcean API to create a new droplet
    protected void deployNewDODroplet(String droplet_name, String region, String size) throws DigitalOceanException, RequestUnsuccessfulException {
        apiClient = new DigitalOceanClient(this.api_key);
        Droplet newDroplet = new Droplet();
        newDroplet.setName(droplet_name);
        newDroplet.setSize(size);
        newDroplet.setRegion(new Region(region));
        newDroplet.setImage(new Image("docker-20-04")); // use docker so we can run a socks5 proxy

        // add your public ssh key to the droplet
        //List<Key> keys = new ArrayList<Key>();
        //keys.add(new Key(123));
        //newDroplet.setKeys(keys);

        this.password = randomPassword(16);
        stdout.println("Generated random password for proxy: " + this.password);

        // set the init script to run on the droplet
        newDroplet.setUserData(droplet_init_script.replace("changeme", this.password));

        // create a new droplet
        stdout.println("Creating new droplet: " + newDroplet.getName());
        this.droplet = apiClient.createDroplet(newDroplet);
    }

    // generate a random password for the socks proxy
    private CharSequence randomPassword(int i) {   
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        StringBuilder sb = new StringBuilder(i);
        for (int j = 0; j < i; j++) {
            int index = (int) (AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }
        return sb;
    }

    // destroy the droplet
    protected void destroyDODroplet() throws DigitalOceanException, RequestUnsuccessfulException {
        DigitalOcean apiClient = new DigitalOceanClient(this.api_key);
        apiClient.deleteDroplet(this.droplet.getId());
        // reset the IP so it gets refreshed for next droplet
        this.ip = null;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Destroying droplet: " + this.droplet.getName());
        try {
            this.destroyDODroplet();
        } catch(Exception e) {
            stdout.println("ERROR - Failed to destroy droplet: " + this.droplet.getName());
            stdout.println(e.getMessage());
        }
        
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu = new ArrayList<JMenuItem>();
		
		JMenuItem enableProxy = new JMenuItem("Enable proxy");
		JMenuItem disableProxy = new JMenuItem("Disable proxy");
		
		IHttpRequestResponse[] selected = invocation.getSelectedMessages();
		
		enableProxy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				configureSocksProxy();
			}
		});
		
		disableProxy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				clearProxyConfiguration();
			}
		});
		
		menu.add(enableProxy);
        menu.add(disableProxy);
		
		return menu;
    }

    @Override
    public String getTabCaption() {
        return "Droplet Proxy";
    }

    @Override
    public Component getUiComponent() {
        return myPanel;
    }

    protected void configureSocksProxy() {
        String ip = "";
        try {
            ip = this.getDropletIP();
        } catch (DigitalOceanException | RequestUnsuccessfulException e) {
            stdout.println("ERROR - Failed to get droplet IP address.");
            e.printStackTrace();
        }
        stdout.println("Configuring Socks5 proxy settings...");
        callbacks.loadConfigFromJson("{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"ip_address\",\"password\":\"changeme\",\"port\":1080,\"use_proxy\":true,\"use_user_options\":false,\"username\":\"burp\"}}}}"
        .replace("ip_address",ip)
        .replace("changeme",this.password));
    }

    public void clearProxyConfiguration() {
        callbacks.loadConfigFromJson("{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"0.0.0.0\",\"password\":\"changeme\",\"port\":1080,\"use_proxy\":false,\"use_user_options\":false,\"username\":\"burp\"}}}}");
    }

    public void setApiKey(String api_key) {
        this.api_key = api_key;
        callbacks.saveExtensionSetting("digitalocean-api-key", api_key);
    }

    public void refreshDroplet() throws DigitalOceanException, RequestUnsuccessfulException {
        stdout.println("Refreshing droplet information...");
        this.droplet = apiClient.getDropletInfo(droplet.getId());;
    }

    public String getDropletIP() throws DigitalOceanException, RequestUnsuccessfulException {
        if(this.ip != null && !this.ip.isEmpty()) {
            return this.ip;
        }
        this.refreshDroplet();
        stdout.println("Getting droplet IP address: " + this.droplet.getName());
        this.ip = this.droplet.getNetworks().getVersion4Networks().get(0).getIpAddress();
        return this.ip;
    }

    public String getDropletStatus() throws DigitalOceanException, RequestUnsuccessfulException {
        this.refreshDroplet();
        return this.droplet.getStatus().toString();
    }
}