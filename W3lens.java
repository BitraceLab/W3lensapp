import com.azure.cosmos.*;
import com.azure.cosmos.models.*;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyOperationResult;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import okhttp3.*;

import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.MonetaryFormat;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.http.HttpService;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class W3LensGUI {
    private static final String YOUR_COSMOS_DB_CONNECTION_STRING = "AccountEndpoint=https://w3lens.documents.azure.com:443/;AccountKey=aTGjEwxErl2Q6nkjuAClNqd9r6B27PoxIrBkpV9625Sy0AZ5yRni7adhfIIGPJSlXtNXxwUEsXUxACDbk6ZBow==;";
    private static final String YOUR_DATABASE_NAME = "w3lens";
    private static final String YOUR_CONTAINER_NAME = "w3lenscontainer";
    private static final Set<String> SANCTIONED_COUNTRIES = new HashSet<>(Arrays.asList("Iran", "North Korea", "Russia"));
    private static final Set<String> SCAM_WALLETS = new HashSet<>(Arrays.asList("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64"));
    private static final Set<String> reportedWallets = new HashSet<>();

    private static JTextArea outputTextArea;

    public static void main(String[] args) {
        // Create and configure the GUI components
        JFrame frame = new JFrame("W3Lens Monitor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 500);

        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());

        JLabel bitcoinLabel = new JLabel("Bitcoin Address:");
        JTextField bitcoinTextField = new JTextField();
        JLabel ethereumLabel = new JLabel("Ethereum Address:");
        JTextField ethereumTextField = new JTextField();
        JButton monitorButton = new JButton("Monitor");
        JButton reportButton = new JButton("Report Wallet");
        JPanel treePanel = new JPanel();

        panel.add(bitcoinLabel, BorderLayout.NORTH);
        panel.add(bitcoinTextField, BorderLayout.CENTER);
        panel.add(ethereumLabel, BorderLayout.CENTER);
        panel.add(ethereumTextField, BorderLayout.SOUTH);
        panel.add(monitorButton, BorderLayout.WEST);
        panel.add(reportButton, BorderLayout.EAST);
        panel.add(treePanel, BorderLayout.SOUTH);

        outputTextArea = new JTextArea();
        outputTextArea.setEditable(false);
        panel.add(new JScrollPane(outputTextArea), BorderLayout.EAST);

        DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("Monitored Addresses");
        DefaultTreeModel treeModel = new DefaultTreeModel(rootNode);
        JTree tree = new JTree(treeModel);
        treePanel.add(tree);

        monitorButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String bitcoinAddress = bitcoinTextField.getText();
                String ethereumAddress = ethereumTextField.getText();

                if (!bitcoinAddress.isEmpty()) {
                    DefaultMutableTreeNode bitcoinNode = new DefaultMutableTreeNode("Bitcoin");
                    DefaultMutableTreeNode bitcoinAddressNode = new DefaultMutableTreeNode(bitcoinAddress);
                    bitcoinNode.add(bitcoinAddressNode);
                    rootNode.add(bitcoinNode);
                    treeModel.reload(rootNode);
                }

                if (!ethereumAddress.isEmpty()) {
                    DefaultMutableTreeNode ethereumNode = new DefaultMutableTreeNode("Ethereum");
                    DefaultMutableTreeNode ethereumAddressNode = new DefaultMutableTreeNode(ethereumAddress);
                    ethereumNode.add(ethereumAddressNode);
                    rootNode.add(ethereumNode);
                    treeModel.reload(rootNode);
                }

                bitcoinTextField.setText("");
                ethereumTextField.setText("");
            }
        });

        reportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) tree.getLastSelectedPathComponent();
                if (selectedNode != null) {
                    String address = selectedNode.getUserObject().toString();
                    reportedWallets.add(address);
                    outputTextArea.append("Wallet reported: " + address + "\n");
                }
            }
        });

        frame.getContentPane().add(panel);
        frame.setVisible(true);

        // Start monitoring Bitcoin and Ethereum
        monitorBitcoin();
        monitorEthereum();
    }

    private static void monitorBitcoin() {
        NetworkParameters params = MainNetParams.get();
        BlockStore blockStore = new MemoryBlockStore(params);
        WalletAppKit walletAppKit = new WalletAppKit(params, blockStore, new File("."), "w3lens");
        walletAppKit.setAutoSave(false);
        walletAppKit.startAsync();
        walletAppKit.awaitRunning();

        walletAppKit.wallet().addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            String bitcoinAddress = tx.getOutput(0).getAddressFromP2PKHScript(params).toString();

            if (reportedWallets.contains(bitcoinAddress)) {
                outputTextArea.append("Reported wallet received coins: " + bitcoinAddress + "\n");
                return;
            }

            BigDecimal btcAmount = MonetaryFormat.BTC.format(new BigDecimal(tx.getValue(wallet).toPlainString()));
            outputTextArea.append("Received " + btcAmount + " BTC at " + bitcoinAddress + "\n");
        });

        walletAppKit.wallet().addCoinsSentEventListener((wallet, tx, prevBalance, newBalance) -> {
            String bitcoinAddress = tx.getOutput(0).getAddressFromP2PKHScript(params).toString();

            if (reportedWallets.contains(bitcoinAddress)) {
                outputTextArea.append("Reported wallet sent coins: " + bitcoinAddress + "\n");
                return;
            }

            BigDecimal btcAmount = MonetaryFormat.BTC.format(new BigDecimal(tx.getValue(wallet).toPlainString()));
            outputTextArea.append("Sent " + btcAmount + " BTC from " + bitcoinAddress + "\n");
        });

        walletAppKit.wallet().addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            String bitcoinAddress = tx.getOutput(0).getAddressFromP2PKHScript(params).toString();

            if (SCAM_WALLETS.contains(bitcoinAddress)) {
                outputTextArea.append("Scam wallet received coins: " + bitcoinAddress + "\n");
            }
        });

        walletAppKit.wallet().addCoinsSentEventListener((wallet, tx, prevBalance, newBalance) -> {
            String bitcoinAddress = tx.getOutput(0).getAddressFromP2PKHScript(params).toString();

            if (SCAM_WALLETS.contains(bitcoinAddress)) {
                outputTextArea.append("Scam wallet sent coins: " + bitcoinAddress + "\n");
            }
        });
    }

    private static void monitorEthereum() {
        Web3j web3j = Web3j.build(new HttpService("https://mainnet.infura.io/v3/your-infura-project-id"));

        web3j.blockFlowable(false).subscribe(ethBlock -> {
            EthBlock.Block block = ethBlock.getBlock();
            List<EthBlock.TransactionResult> transactions = block.getTransactions();

            for (EthBlock.TransactionResult transactionResult : transactions) {
                EthBlock.TransactionObject transaction = (EthBlock.TransactionObject) transactionResult.get();
                String ethereumAddress = transaction.getTo();

                if (reportedWallets.contains(ethereumAddress)) {
                    outputTextArea.append("Reported wallet received ETH: " + ethereumAddress + "\n");
                    return;
                }

                BigDecimal ethAmount = new BigDecimal(transaction.getValue()).divide(BigDecimal.TEN.pow(18));
                outputTextArea.append("Received " + ethAmount + " ETH at " + ethereumAddress + "\n");
            }
        });
    }

    private static void addToCosmosDB(String address, String type) {
        CosmosClient cosmosClient = new CosmosClientBuilder()
                .endpoint(YOUR_COSMOS_DB_CONNECTION_STRING)
                .credential(new DefaultAzureCredentialBuilder().build())
                .consistencyLevel(ConsistencyLevel.EVENTUAL)
                .buildClient();

        CosmosContainer container = cosmosClient.getDatabase(YOUR_DATABASE_NAME)
                .getContainer(YOUR_CONTAINER_NAME);

        Wallet wallet = new Wallet(address, type);
        container.createItem(wallet, new PartitionKey(wallet.getType()), new CosmosItemRequestOptions());
        outputTextArea.append("Added to Cosmos DB: " + wallet.toString() + "\n");

        cosmosClient.close();
    }

    private static class Wallet {
        private final String address;
        private final String type;

        public Wallet(String address, String type) {
            this.address = address;
            this.type = type;
        }

        public String getAddress() {
            return address;
        }

        public String getType() {
            return type;
        }

        @Override
        public String toString() {
            return "Wallet{" +
                    "address='" + address + '\'' +
                    ", type='" + type + '\'' +
                    '}';
        }
    }
}

