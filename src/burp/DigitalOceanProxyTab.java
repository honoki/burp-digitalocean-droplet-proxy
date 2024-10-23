package burp;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;

import com.myjeeva.digitalocean.exception.DigitalOceanException;
import com.myjeeva.digitalocean.exception.RequestUnsuccessfulException;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JTextPane;

public class DigitalOceanProxyTab extends JPanel {
    private BurpExtender burp;
	private JPasswordField textField_1;
    private JTextPane textPane;
    // status of the proxy: 0 = not deployed, 1 = deployed and waiting for network, 2 = deployed and ready
    private int STATUS = 0;
    private int NB_DROPLETS = 2;

    public DigitalOceanProxyTab(BurpExtender burp) {
		
		this.burp = burp;
        this.burp.setProxyTab(this);
		
		JLabel lblApiKey = new JLabel("DigitalOcean API key");
        JButton btnDestroy = new JButton("Destroy");
        this.textPane = new JTextPane();
				
		JButton btnDeploy = new JButton("Deploy");
		btnDeploy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				burp.setApiKey(textField_1.getText());
				
				try {
                    // First get list of existing droplet in account that weren't deleted yet
                    int nbExisting = burp.loadExistingProxyDroplets();
                    if(nbExisting > 0) {
                        textPane.setText("WARNING: there are still "+nbExisting+" proxies deployed - they will be removed when hitting the Destroy button.");
                    }


                    btnDeploy.setEnabled(false);
                    textPane.setText(textPane.getText() + "\nDeploying "+NB_DROPLETS+" proxy droplets to DigitalOcean...");
                    for(int i=0; i<NB_DROPLETS; i++) {
                        burp.deployNewDODroplet("burp-proxy-"+i,"nyc1","s-1vcpu-1gb");
                    }
                    textPane.setText(textPane.getText() + "\nProxy droplets are deploying, waiting for first droplet to come online...");
                    STATUS = 1;
                    Thread thread = new Thread(() -> {
                        // as long as status is "new", wait 60 seconds and check again
                        try {
                            while(burp.getDropletStatus().equals("new")) {
                                textPane.setText(textPane.getText() + "\nProxy droplet is not ready yet, waiting 60 seconds...");
                                try {
                                    Thread.sleep(60000);
                                } catch (InterruptedException e2) {
                                    e2.printStackTrace();
                                }
                            }
                        } catch (DigitalOceanException | RequestUnsuccessfulException e1) {
                            e1.printStackTrace();
                        }
                        finishedWaiting();
                        btnDestroy.setEnabled(true);
                    });
                    thread.start();
                } catch (DigitalOceanException | RequestUnsuccessfulException e1) {
                    burp.stdout.println("Error deploying droplet: " + e1.getMessage());
                    e1.printStackTrace();
                }
			}
		});
		
		textField_1 = new JPasswordField(burp.api_key);
		textField_1.setColumns(10);
		
		btnDestroy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                // you can't destroy what is never built
                if(STATUS == 0) return;
                try {
                    btnDestroy.setEnabled(false);
                    textPane.setText(textPane.getText() +"\nDestroying proxies...");
                    burp.destroyAllDroplets();
                    textPane.setText(textPane.getText() +"\nResetting Burp socks proxy config...");
                    burp.clearProxyConfiguration();
                    textPane.setText(textPane.getText() +"\nProxies destroyed.");
                    STATUS = 0;
                    btnDeploy.setEnabled(true);
                } catch (Exception e1) {
                    burp.stdout.println("Error destroying proxies: " + e1.getMessage());
                    e1.printStackTrace();
                }
				
			}
		});
		
		JButton btnEnableProxy = new JButton("Enable Proxy");
		JButton btnDisableProxy = new JButton("Disable Proxy");
        btnEnableProxy.setEnabled(!burp.isProxyEnabled);
        btnDisableProxy.setEnabled(burp.isProxyEnabled);
		JButton btnCycleNextDroplet = new JButton("Cycle Next Droplet");
		btnEnableProxy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				burp.configureSocksProxy();
                btnDisableProxy.setEnabled(true);
                btnEnableProxy.setEnabled(false);
			}
		});

		btnDisableProxy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				burp.clearProxyConfiguration();
                btnDisableProxy.setEnabled(false);
                btnEnableProxy.setEnabled(true);
				textPane.setText(textPane.getText() + "\nProxy disabled.");
			}
		});

		btnCycleNextDroplet.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					burp.cycleProxy();
				} catch (Exception ex) {
					burp.stdout.println("Error cycling proxy: " + ex.getMessage());
					ex.printStackTrace();
				}
			}
		});

		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(45)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(textPane, GroupLayout.PREFERRED_SIZE, 615, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnDeploy)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(lblApiKey)
							.addGap(43)
							.addComponent(textField_1, GroupLayout.PREFERRED_SIZE, 318, GroupLayout.PREFERRED_SIZE)
							.addGap(3)
							.addComponent(btnDestroy))
						// New row for additional buttons
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(btnEnableProxy)
							.addGap(10)
							.addComponent(btnDisableProxy)
							.addGap(10)
							.addComponent(btnCycleNextDroplet)))
					.addContainerGap(20, Short.MAX_VALUE))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
					.addGroup(groupLayout.createSequentialGroup()
						.addGap(40)
						.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
							.addGroup(groupLayout.createSequentialGroup()
								.addGap(4)
								.addComponent(lblApiKey))
							.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
								.addComponent(btnDeploy)
								.addComponent(textField_1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(btnDestroy)))
						.addGap(18)
						// New row for additional buttons
						.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
							.addComponent(btnEnableProxy)
							.addComponent(btnDisableProxy)
							.addComponent(btnCycleNextDroplet))
						.addGap(18)
						.addPreferredGap(ComponentPlacement.UNRELATED)
						.addComponent(textPane, GroupLayout.DEFAULT_SIZE, 49, Short.MAX_VALUE)
						.addGap(38))
		);
		setLayout(groupLayout);

        // automatically execute deploy if api key is known
        if(burp.api_key != null && !burp.api_key.isEmpty()) {
            btnDeploy.doClick();
        }

	}

    protected void finishedWaiting() {
        // don't execute this if the proxy is destoryed in the meantime
        if(STATUS == 0)
            return;
        textPane.setText(textPane.getText() + "\nProxy droplet is ready, click 'enable proxy' to route traffic...");
        // burp.configureSocksProxy();
        // textPane.setText(textPane.getText() +"\nProxy settings configured.");
        // textPane.setText(textPane.getText() +"\nProxy is ready to use.");
        STATUS = 2;
    }

    protected void log(String log) {
        textPane.setText(textPane.getText() + "\n"+log);
    }
}
