package burp;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
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
	private JTextField textField_1;
    private JTextPane textPane;
    // status of the proxy: 0 = not deployed, 1 = deployed and waiting for network, 2 = deployed and ready
    private int STATUS = 0;

    public DigitalOceanProxyTab(BurpExtender burp) {
		
		this.burp = burp;
		
		JLabel lblApiKey = new JLabel("DigitalOcean API key");
        this.textPane = new JTextPane();
				
		JButton btnDeploy = new JButton("Deploy");
		btnDeploy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				burp.setApiKey(textField_1.getText());
				
				try {
                    textPane.setText("Deploying proxy to DigitalOcean...");
                    burp.deployNewDODroplet("burp-proxy","nyc1","s-1vcpu-1gb");
                    textPane.setText(textPane.getText() + "\nProxy droplet is deploying, waiting for network...");
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
                    });
                    thread.start();
                } catch (DigitalOceanException | RequestUnsuccessfulException e1) {
                    burp.stdout.println("Error deploying droplet: " + e1.getMessage());
                    e1.printStackTrace();
                }
			}
		});
		
		textField_1 = new JTextField(burp.api_key);
		textField_1.setColumns(10);
		
		JButton btnDestroy = new JButton("Destroy");
		btnDestroy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                // you can't destroy what is never built
                if(STATUS == 0) return;
                try {
                    textPane.setText(textPane.getText() +"\nDestroying proxy droplet...");
                    burp.destroyDODroplet();
                    textPane.setText(textPane.getText() +"\nRemoving Burp socks proxy config...");
                    burp.clearProxyConfiguration();
                    textPane.setText(textPane.getText() +"\nProxy destroyed.");
                    STATUS = 0;
                } catch (Exception e1) {
                    burp.stdout.println("Error destroying droplet: " + e1.getMessage());
                    e1.printStackTrace();
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
							.addComponent(btnDestroy)))
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
        textPane.setText(textPane.getText() + "\nProxy droplet is ready, configuring proxy...");
        burp.configureSocksProxy();
        textPane.setText(textPane.getText() +"\nProxy settings configured.");
        textPane.setText(textPane.getText() +"\nProxy is ready to use.");
        STATUS = 2;
    }
}
