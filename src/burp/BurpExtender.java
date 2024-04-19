package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
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
    private int proxyCount = 0;
    private DigitalOcean apiClient;

    // gui elements
	public DigitalOceanProxyTab myPanel;

    // keep a copy of our proxy droplets
    ArrayList<Droplet> droplets = new ArrayList<Droplet>();
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
        proxyCount++;
        apiClient = new DigitalOceanClient(this.api_key);
        Droplet newDroplet = new Droplet();
        newDroplet.setName(droplet_name);
        newDroplet.setSize(size);
        newDroplet.setRegion(new Region(region));
        newDroplet.setImage(new Image("docker-20-04")); // use docker so we can run a socks5 proxy
        newDroplet.setTags(Arrays.asList("burp-proxy")); // set a tag so they get removed when hitting "destroy"

        // add your public ssh key to the droplet
        //List<Key> keys = new ArrayList<Key>();
        //keys.add(new Key(123));
        //newDroplet.setKeys(keys);

        // generate a new password if we don't have one yet (first droplet)
        if(this.password == null) {
            this.password = randomPassword(16); 
            stdout.println("Generated random password for proxy: " + this.password);
        }

        // set the init script to run on the droplet
        newDroplet.setUserData(droplet_init_script.replace("changeme", this.password));

        // create a new droplet
        stdout.println("Creating new droplet: " + newDroplet.getName());
        this.droplets.add(apiClient.createDroplet(newDroplet));
    }

    // get a list of droplets named burp-proxy* that already exist on the account
    // note that these cannot be used because the proxy password is randomized;
    // return the number of existing proxy droplets found.
    protected int loadExistingProxyDroplets() {
        apiClient = new DigitalOceanClient(this.api_key);
        Droplets existing_droplets;
        try {
            existing_droplets = apiClient.getAvailableDropletsByTagName("burp-proxy", 1, 100);
            return existing_droplets.getDroplets().size();
        } catch (DigitalOceanException | RequestUnsuccessfulException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return -1;
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


    // destroy one droplet by its id
    protected void destroyDODroplet(int droplet_id) throws DigitalOceanException, RequestUnsuccessfulException {
        DigitalOcean apiClient = new DigitalOceanClient(this.api_key);
        stdout.println("Destroying droplets");
        apiClient.deleteDroplet(droplet_id);
        // reset the IP so it gets refreshed for next droplet
        this.ip = null;
    }

    // destroy all droplets
    protected void destroyAllDroplets() throws DigitalOceanException, RequestUnsuccessfulException {
        DigitalOcean apiClient = new DigitalOceanClient(this.api_key);
        apiClient.deleteDropletByTagName("burp-proxy");
        for(Droplet d : this.droplets) {
            stdout.println("Destroying droplet: " + d.getName());
            apiClient.deleteDroplet(d.getId());
        }
        // reset the IP so it gets refreshed for next droplet
        this.ip = null;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Destroying all droplets...");
        try {
            this.destroyAllDroplets();
        } catch(Exception e) {
            stdout.println("ERROR - Failed to destroy droplets");
            stdout.println(e.getMessage());
        }
        
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu = new ArrayList<JMenuItem>();
		
		JMenuItem enableProxy = new JMenuItem("Enable proxy");
		JMenuItem disableProxy = new JMenuItem("Disable proxy");
        JMenuItem cycleProxy = new JMenuItem("Cycle nextdroplet");
		
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

        cycleProxy.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cycleProxy();
            }
        });
		
		menu.add(enableProxy);
        menu.add(disableProxy);
        menu.add(cycleProxy);
		
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
            ip = this.getCurrentDropletIP();
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

    public void cycleProxy() {
        try {
            this.cycleNextDroplet();
        } catch (Exception e) {
            return;
        }
    }

    public void setApiKey(String api_key) {
        this.api_key = api_key;
        callbacks.saveExtensionSetting("digitalocean-api-key", api_key);
    }

    public void refreshDroplet() throws DigitalOceanException, RequestUnsuccessfulException {
        stdout.println("Refreshing droplet information...");
        this.droplets.set(0, apiClient.getDropletInfo(this.droplets.get(0).getId()));
    }

    // cycle to the next droplet in the list
    public void cycleNextDroplet() throws DigitalOceanException, RequestUnsuccessfulException {
        stdout.println("Updating droplet list...");
        int dropletToRemoveID = this.droplets.get(0).getId();
        
        // remove the first droplet in the list
        this.droplets.remove(0);
        // configure proxy settings for the next droplet
        this.configureSocksProxy();
        
        Thread thread = new Thread(() -> {
            try {
                // destroy the proxy we just removed from the list
                this.destroyDODroplet(dropletToRemoveID);
                // and spin up a new one so we're ready for the next cycle
                this.deployNewDODroplet("burp-proxy-"+proxyCount,"nyc1","s-1vcpu-1gb");
            } catch (DigitalOceanException | RequestUnsuccessfulException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        });
        thread.start();
    }

    public String getCurrentDropletIP() throws DigitalOceanException, RequestUnsuccessfulException {
        //if(this.ip != null && !this.ip.isEmpty()) {
        //    return this.ip;
        //}
        this.refreshDroplet();
        stdout.println("Getting droplet IP address: " + this.droplets.get(0).getName());
        this.ip = this.droplets.get(0).getNetworks().getVersion4Networks().get(0).getIpAddress();
        return this.ip;
    }

    public String getDropletStatus() throws DigitalOceanException, RequestUnsuccessfulException {
        this.refreshDroplet();
        return this.droplets.get(0).getStatus().toString();
    }
}